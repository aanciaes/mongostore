// Copyright 2012 The KidStuff Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mongostore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	mongoOperationTimeout     = 5 * time.Second
	mongoColumnIdName         = "_id"
	mongoColumnModifiedAtName = "modified"
)

var (
	ErrInvalidId = errors.New("mongoStore: invalid session id")
)

// Session object store in MongoDB
type Session struct {
	Id       primitive.ObjectID `bson:"_id,omitempty"`
	Data     string
	Modified time.Time
}

// MongoStore stores sessions in MongoDB
type MongoStore struct {
	Codecs  []securecookie.Codec
	Options *sessions.Options
	Token   TokenGetSeter
	coll    *mongo.Collection
}

// NewMongoStore returns a new MongoStore.
// Set ensureTTL to true let the database auto-remove expired object by maxAge.
func NewMongoStore(c *mongo.Collection, cookieOptions sessions.Options, ensureTTL bool, keyPairs ...[]byte) (*MongoStore, error) {
	if cookieOptions.MaxAge <= 0 {
		return nil, fmt.Errorf("error initializing mongo store: max age less than or zero or not provided")
	}

	store := &MongoStore{
		Codecs:  securecookie.CodecsFromPairs(keyPairs...),
		Options: &cookieOptions,
		Token:   &CookieToken{},
		coll:    c,
	}

	store.MaxAge(cookieOptions.MaxAge)
	store.MaxLength(8192)

	modifiedAtIndex := getModifiedAtIndex(c)

	if !ensureTTL {
		// Delete index
		return store, removeModifiedAtIndex(c, modifiedAtIndex)
	}

	// Create or update index
	return store, createOrUpdateModifiedAtIndex(c, cookieOptions.MaxAge, modifiedAtIndex)
}

func getModifiedAtIndex(c *mongo.Collection) *mongo.IndexSpecification {
	cur, err := c.Indexes().List(context.Background(), nil)
	if err != nil {
		panic(err)
	}
	for cur.Next(context.Background()) {
		index := mongo.IndexSpecification{}
		_ = cur.Decode(&index)

		if strings.HasPrefix(index.Name, mongoColumnModifiedAtName) {
			return &index
		}
	}

	return nil
}

func createOrUpdateModifiedAtIndex(c *mongo.Collection, maxAge int, modifiedAtIndex *mongo.IndexSpecification) error {
	expireAfter := time.Duration(maxAge) * time.Second

	if modifiedAtIndex != nil && float64(*modifiedAtIndex.ExpireAfterSeconds) == expireAfter.Seconds() {
		return nil
	}

	if modifiedAtIndex != nil {
		// Indexes cannot be updated, we need to remove and create a new one
		if err := removeModifiedAtIndex(c, modifiedAtIndex); err != nil {
			return err
		}
	}

	indexOptions := options.Index()
	indexOptions = indexOptions.SetSparse(true)
	indexOptions = indexOptions.SetExpireAfterSeconds(int32(expireAfter.Seconds()))

	indexModel := mongo.IndexModel{
		Keys:    bson.M{mongoColumnModifiedAtName: 1},
		Options: indexOptions,
	}

	ctx, cancel := context.WithTimeout(context.Background(), mongoOperationTimeout)
	defer cancel()

	_, err := c.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		return err
	}

	return nil
}

func removeModifiedAtIndex(c *mongo.Collection, modifiedAtIndex *mongo.IndexSpecification) error {
	if modifiedAtIndex != nil {
		ctx, cancel := context.WithTimeout(context.Background(), mongoOperationTimeout)
		defer cancel()

		_, err := c.Indexes().DropOne(ctx, modifiedAtIndex.Name)
		if err != nil {
			return err
		}
	}

	return nil
}

// Get registers and returns a session for the given name and session store.
// It returns a new session if there are no sessions registered for the name.
func (m *MongoStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(m, name)
}

// New returns a session for the given name without adding it to the registry.
func (m *MongoStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(m, name)
	session.Options = &sessions.Options{
		Path:     m.Options.Path,
		MaxAge:   m.Options.MaxAge,
		Domain:   m.Options.Domain,
		Secure:   m.Options.Secure,
		HttpOnly: m.Options.HttpOnly,
	}
	session.IsNew = true
	var err error
	if cook, errToken := m.Token.GetToken(r, name); errToken == nil {
		err = securecookie.DecodeMulti(name, cook, &session.ID, m.Codecs...)
		if err == nil {
			err = m.load(session)
			if err == nil {
				session.IsNew = false
			} else {
				err = nil
			}
		}
	}
	return session, err
}

// Save saves all sessions registered for the current request.
func (m *MongoStore) Save(_ *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	if session.Options.MaxAge < 0 {
		if err := m.delete(session); err != nil {
			return err
		}
		m.Token.SetToken(w, session.Name(), "", session.Options)
		return nil
	}

	if session.ID == "" {
		session.ID = primitive.NewObjectID().Hex()
	}

	if err := m.upsert(session); err != nil {
		return err
	}

	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, m.Codecs...)
	if err != nil {
		return err
	}

	m.Token.SetToken(w, session.Name(), encoded, session.Options)
	return nil
}

// MaxAge sets the maximum age for the store and the underlying cookie
// implementation. Individual sessions can be deleted by setting Options.MaxAge
// = -1 for that session.
func (m *MongoStore) MaxAge(age int) {
	m.Options.MaxAge = age

	// Set the maxAge for each secure-cookie instance.
	for _, codec := range m.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

func (m *MongoStore) MaxLength(length int) {
	// Set the maxLength for each secure-cookie instance.
	for _, codec := range m.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxLength(length)
		}
	}
}

func (m *MongoStore) load(session *sessions.Session) error {
	objID, err := primitive.ObjectIDFromHex(session.ID)
	if err != nil {
		return ErrInvalidId
	}

	s := Session{}

	ctx, cancel := context.WithTimeout(context.Background(), mongoOperationTimeout)
	defer cancel()

	if err := m.coll.FindOne(ctx, bson.M{mongoColumnIdName: objID}).Decode(&s); err != nil {
		return err
	}

	if err := securecookie.DecodeMulti(session.Name(), s.Data, &session.Values, m.Codecs...); err != nil {
		return err
	}

	return nil
}

func (m *MongoStore) upsert(session *sessions.Session) error {
	objID, err := primitive.ObjectIDFromHex(session.ID)
	if err != nil {
		return ErrInvalidId
	}

	var modified time.Time
	if val, ok := session.Values[mongoColumnModifiedAtName]; ok {
		modified, ok = val.(time.Time)
		if !ok {
			return errors.New("mongoStore: invalid modified value")
		}
	} else {
		modified = time.Now()
	}

	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values, m.Codecs...)
	if err != nil {
		return err
	}

	s := Session{
		Id:       objID,
		Data:     encoded,
		Modified: modified,
	}

	opts := options.Update().SetUpsert(true)
	filter := bson.M{mongoColumnIdName: s.Id}
	updateData := bson.M{"$set": s}

	ctx, cancel := context.WithTimeout(context.Background(), mongoOperationTimeout)
	defer cancel()

	if _, err = m.coll.UpdateOne(ctx, filter, updateData, opts); err != nil {
		return err
	}

	return nil
}

func (m *MongoStore) delete(session *sessions.Session) error {
	objID, err := primitive.ObjectIDFromHex(session.ID)
	if err != nil {
		return ErrInvalidId
	}

	ctx, cancel := context.WithTimeout(context.Background(), mongoOperationTimeout)
	defer cancel()

	if _, err = m.coll.DeleteOne(ctx, bson.M{mongoColumnIdName: objID}); err != nil {
		return err
	}

	return nil
}
