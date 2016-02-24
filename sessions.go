// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gaesessions

import (
	"bytes"
	"encoding/base32"
	"encoding/gob"
	"net/http"
	"strings"
	"time"

	"google.golang.org/appengine"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/memcache"
	"google.golang.org/appengine/log"
	"golang.org/x/net/context"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

// MemcacheDatastoreStore -----------------------------------------------------

const DefaultNonPersistentSessionDuration = time.Duration(24) * time.Hour
const defaultKind = "Session"

// NewMemcacheDatastoreStore returns a new MemcacheDatastoreStore.
//
// The kind argument is the kind name used to store the session data.
// If empty it will use "Session".
//
// See NewCookieStore() for a description of the other parameters.
func NewMemcacheDatastoreStore(kind, keyPrefix string, nonPersistentSessionDuration time.Duration, keyPairs ...[]byte) *MemcacheDatastoreStore {
	if kind == "" {
		kind = defaultKind
	}
	if keyPrefix == "" {
		keyPrefix = "gorilla.appengine.sessions."
	}
	return &MemcacheDatastoreStore{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: 86400 * 30,
		},
		kind:   kind,
		prefix: keyPrefix,
		nonPersistentSessionDuration: nonPersistentSessionDuration,
	}
}

type MemcacheDatastoreStore struct {
	Codecs                       []securecookie.Codec
	Options                      *sessions.Options // default configuration
	kind                         string
	prefix                       string
	nonPersistentSessionDuration time.Duration
}

// Get returns a session for the given name after adding it to the registry.
//
// See CookieStore.Get().
func (s *MemcacheDatastoreStore) Get(r *http.Request, name string) (
	*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
//
// See CookieStore.New().
func (s *MemcacheDatastoreStore) New(r *http.Request, name string) (*sessions.Session,
	error) {
	session := sessions.NewSession(s, name)
	session.Options = &(*s.Options)
	session.IsNew = true
	var err error
	if cookie, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, cookie.Value, &session.ID,
			s.Codecs...)
		if err == nil {
			c := appengine.NewContext(r)
			err = loadFromMemcache(c, session)
			if err == memcache.ErrCacheMiss {
				err = loadFromDatastore(c, s.kind, session)
			}
			if err == nil {
				session.IsNew = false
			}
		}
	}
	return session, err
}

// Save adds a single session to the response.
func (s *MemcacheDatastoreStore) Save(r *http.Request, w http.ResponseWriter,
	session *sessions.Session) error {
	if session.ID == "" {
		session.ID = s.prefix +
			strings.TrimRight(
				base32.StdEncoding.EncodeToString(
					securecookie.GenerateRandomKey(32)), "=")
	}
	c := appengine.NewContext(r)
	if err := saveToMemcache(c, s.nonPersistentSessionDuration, session); err != nil {
		return err
	}
	if err := saveToDatastore(c, s.kind, s.nonPersistentSessionDuration, session); err != nil {
		return err
	}
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID,
		s.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded,
		session.Options))
	return nil
}

// DatastoreStore -------------------------------------------------------------

// Session is used to load and save session data in the datastore.
type Session struct {
	Date           time.Time
	ExpirationDate time.Time
	Value          []byte
}

// NewDatastoreStore returns a new DatastoreStore.
//
// The kind argument is the kind name used to store the session data.
// If empty it will use "Session".
//
// See NewCookieStore() for a description of the other parameters.
func NewDatastoreStore(kind string, nonPersistentSessionDuration time.Duration, keyPairs ...[]byte) *DatastoreStore {
	if kind == "" {
		kind = "Session"
	}
	return &DatastoreStore{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: 86400 * 30,
		},
		kind: kind,
		nonPersistentSessionDuration: nonPersistentSessionDuration,
	}
}

// DatastoreStore stores sessions in the App Engine datastore.
type DatastoreStore struct {
	Codecs                       []securecookie.Codec
	Options                      *sessions.Options // default configuration
	kind                         string
	nonPersistentSessionDuration time.Duration
}

// Get returns a session for the given name after adding it to the registry.
//
// See CookieStore.Get().
func (s *DatastoreStore) Get(r *http.Request, name string) (*sessions.Session,
	error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
//
// See CookieStore.New().
func (s *DatastoreStore) New(r *http.Request, name string) (*sessions.Session,
	error) {
	session := sessions.NewSession(s, name)
	session.Options = &(*s.Options)
	session.IsNew = true
	var err error
	if cookie, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, cookie.Value, &session.ID,
			s.Codecs...)
		if err == nil {
			c := appengine.NewContext(r)
			err = loadFromDatastore(c, s.kind, session)
			if err == nil {
				session.IsNew = false
			}
		}
	}
	return session, err
}

// Save adds a single session to the response.
func (s *DatastoreStore) Save(r *http.Request, w http.ResponseWriter,
	session *sessions.Session) error {
	if session.ID == "" {
		session.ID =
			strings.TrimRight(
				base32.StdEncoding.EncodeToString(
					securecookie.GenerateRandomKey(32)), "=")
	}
	c := appengine.NewContext(r)
	if err := saveToDatastore(c, s.kind, s.nonPersistentSessionDuration, session); err != nil {
		return err
	}
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID,
		s.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded,
		session.Options))
	return nil
}

// save writes encoded session.Values to datastore.
func saveToDatastore(c context.Context, kind string,
	nonPersistentSessionDuration time.Duration,
	session *sessions.Session) error {
	if len(session.Values) == 0 {
		// Don't need to write anything.
		return nil
	}
	serialized, err := serialize(session.Values)
	if err != nil {
		return err
	}
	k := datastore.NewKey(c, kind, session.ID, 0, nil)
	now := time.Now()
	var expirationDate time.Time
	var expiration time.Duration
	if session.Options.MaxAge > 0 {
		expiration = time.Duration(session.Options.MaxAge) * time.Second
	} else {
		expiration = nonPersistentSessionDuration
	}
	if expiration > 0 {
		expirationDate = now.Add(expiration)
		k, err = datastore.Put(c, k, &Session{
			Date:           now,
			ExpirationDate: expirationDate,
			Value:          serialized,
		})
		if err != nil {
			return err
		}
	} else {
		err = datastore.Delete(c, k)
		if err != nil {
			return err
		}
	}
	return nil
}

// load gets a value from datastore and decodes its content into
// session.Values.
func loadFromDatastore(c context.Context, kind string,
	session *sessions.Session) error {
	k := datastore.NewKey(c, kind, session.ID, 0, nil)
	entity := Session{}
	if err := datastore.Get(c, k, &entity); err != nil {
		return err
	}
	if err := deserialize(entity.Value, &session.Values); err != nil {
		return err
	}
	return nil
}

// remove expired sessions in the datastore. you can call this function
// from a cron job.
//
// sample handler config in app.yaml:
// handlers:
// - url: /tasks/removeExpiredSessions
//   script: _go_app
//   login: admin
// - url: /.*
//   script: _go_app
//
// handler registration code:
// http.HandleFunc("/tasks/removeExpiredSessions", removeExpiredSessionsHandler)
//
// sample handler:
// func removeExpiredSessionsHandler(w http.ResponseWriter, r *http.Request) {
//	c := appengine.NewContext(r)
//	gaesessions.RemoveExpiredDatastoreSessions(c, "")
// }
//
// sample cron.yaml:
// cron:
// - description: expired session removal job
//   url: /tasks/removeExpiredSessions
//   schedule: every 1 minutes
func RemoveExpiredDatastoreSessions(c context.Context, kind string) error {
	keys, err := findExpiredDatastoreSessionKeys(c, kind)
	if err != nil {
		return err
	}
	return datastore.DeleteMulti(c, keys)
}

func findExpiredDatastoreSessionKeys(c context.Context, kind string) (keys []*datastore.Key, err error) {
	if kind == "" {
		kind = defaultKind
	}
	now := time.Now()
	q := datastore.NewQuery(kind).Filter("ExpirationDate <=", now).KeysOnly()
	keys, err = q.GetAll(c, nil)
	return
}

// MemcacheStore --------------------------------------------------------------

// NewMemcacheStore returns a new MemcacheStore.
//
// The keyPrefix argument is the prefix used for memcache keys. If empty it
// will use "gorilla.appengine.sessions.".
//
// See NewCookieStore() for a description of the other parameters.
func NewMemcacheStore(keyPrefix string, nonPersistentSessionDuration time.Duration, keyPairs ...[]byte) *MemcacheStore {
	if keyPrefix == "" {
		keyPrefix = "gorilla.appengine.sessions."
	}
	return &MemcacheStore{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: 86400 * 30,
		},
		prefix: keyPrefix,
		nonPersistentSessionDuration: nonPersistentSessionDuration,
	}
}

// MemcacheStore stores sessions in the App Engine memcache.
type MemcacheStore struct {
	Codecs                       []securecookie.Codec
	Options                      *sessions.Options // default configuration
	prefix                       string
	nonPersistentSessionDuration time.Duration
}

// Get returns a session for the given name after adding it to the registry.
//
// See CookieStore.Get().
func (s *MemcacheStore) Get(r *http.Request, name string) (*sessions.Session,
	error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
//
// See CookieStore.New().
func (s *MemcacheStore) New(r *http.Request, name string) (*sessions.Session,
	error) {
	session := sessions.NewSession(s, name)
	session.Options = &(*s.Options)
	session.IsNew = true
	var err error
	if cookie, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, cookie.Value, &session.ID,
			s.Codecs...)
		if err == nil {
			c := appengine.NewContext(r)
			err = loadFromMemcache(c, session)
			if err == nil {
				session.IsNew = false
			}
		}
	}
	return session, err
}

// Save adds a single session to the response.
func (s *MemcacheStore) Save(r *http.Request, w http.ResponseWriter,
	session *sessions.Session) error {
	if session.ID == "" {
		session.ID = s.prefix +
			strings.TrimRight(
				base32.StdEncoding.EncodeToString(
					securecookie.GenerateRandomKey(32)), "=")
	}
	c := appengine.NewContext(r)
	if err := saveToMemcache(c, s.nonPersistentSessionDuration, session); err != nil {
		return err
	}
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID,
		s.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded,
		session.Options))
	return nil
}

// save writes encoded session.Values to memcache.
func saveToMemcache(c context.Context,
	nonPersistentSessionDuration time.Duration,
	session *sessions.Session) error {
	if len(session.Values) == 0 {
		// Don't need to write anything.
		return nil
	}
	serialized, err := serialize(session.Values)
	if err != nil {
		return err
	}
	var expiration time.Duration
	if session.Options.MaxAge > 0 {
		expiration = time.Duration(session.Options.MaxAge) * time.Second
	} else {
		expiration = nonPersistentSessionDuration
	}
	if expiration > 0 {
		log.Debugf(c, "MemcacheStore.save. session.ID=%s, expiration=%s",
			session.ID, expiration)
		err = memcache.Set(c, &memcache.Item{
			Key:        session.ID,
			Value:      serialized,
			Expiration: expiration,
		})
		if err != nil {
			return err
		}
	} else {
		err = memcache.Delete(c, session.ID)
		if err != nil {
			return err
		}
		log.Debugf(c, "MemcacheStore.save. delete session.ID=%s", session.ID)
	}
	return nil
}

// load gets a value from memcache and decodes its content into session.Values.
func loadFromMemcache(c context.Context, session *sessions.Session) error {
	item, err := memcache.Get(c, session.ID)
	if err != nil {
		return err
	}
	if err := deserialize(item.Value, &session.Values); err != nil {
		return err
	}
	return nil
}

// Serialization --------------------------------------------------------------

// serialize encodes a value using gob.
func serialize(src interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(src); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// deserialize decodes a value using gob.
func deserialize(src []byte, dst interface{}) error {
	dec := gob.NewDecoder(bytes.NewBuffer(src))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}
