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

	"appengine"
	"appengine/datastore"
	"appengine/delay"
	"appengine/memcache"
	"appengine/taskqueue"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

// MemcacheDatastoreStore -----------------------------------------------------

// NewMemcacheDatastoreStore returns a new MemcacheDatastoreStore.
//
// The kind argument is the kind name used to store the session data.
// If empty it will use "Session".
//
// See NewCookieStore() for a description of the other parameters.
func NewMemcacheDatastoreStore(kind, keyPrefix string, keyPairs ...[]byte) *MemcacheDatastoreStore {
	if kind == "" {
		kind = "Session"
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
	}
}

type MemcacheDatastoreStore struct {
	Codecs  []securecookie.Codec
	Options *sessions.Options // default configuration
	kind    string
	prefix  string
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
	if err := saveToMemcache(c, session); err != nil {
		return err
	}
	if err := saveToDatastore(c, s.kind, session); err != nil {
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
func NewDatastoreStore(kind string, keyPairs ...[]byte) *DatastoreStore {
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
	}
}

// DatastoreStore stores sessions in the App Engine datastore.
type DatastoreStore struct {
	Codecs  []securecookie.Codec
	Options *sessions.Options // default configuration
	kind    string
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
	if err := saveToDatastore(c, s.kind, session); err != nil {
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
func saveToDatastore(c appengine.Context, kind string,
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
	if session.Options.MaxAge > 0 {
		expiration := time.Duration(session.Options.MaxAge) * time.Second
		expirationDate = now.Add(expiration)

		k, err = datastore.Put(c, k, &Session{
			Date:           now,
			ExpirationDate: expirationDate,
			Value:          serialized,
		})
		if err != nil {
			return err
		}

		task, err := expireSessionLater.Task(kind, session.ID)
		if err != nil {
			return err
		}
		task.ETA = expirationDate
		task, err = taskqueue.Add(c, task, "")
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
func loadFromDatastore(c appengine.Context, kind string,
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

var expireSessionLater = delay.Func("expireSession", expireSession)

func expireSession(c appengine.Context, kind, sessionID string) error {
	c.Debugf("DatastoreStore expireSession start session.ID=%s", sessionID)
	k := datastore.NewKey(c, kind, sessionID, 0, nil)
	entity := Session{}
	if err := datastore.Get(c, k, &entity); err != nil {
		if err == datastore.ErrNoSuchEntity {
			// Already deleted. Do nothing.
			return nil
		}
		c.Errorf("DatastoreStore expireSession datastore.Get failed. session.ID=%s, err=%s", sessionID, err.Error())
		return err
	}
	session := sessions.Session{
		Values: make(map[interface{}]interface{}),
	}
	if err := deserialize(entity.Value, &session.Values); err != nil {
		c.Errorf("DatastoreStore expireSession deserialize failed. session.ID=%s, err=%s", sessionID, err.Error())
		return err
	}
	now := time.Now()
	if now.After(entity.ExpirationDate) {
		err := datastore.Delete(c, k)
		if err != nil {
			c.Errorf("DatastoreStore expireSession delete session.ID=%s, now=%s, expirationDate=%s, err=%s", sessionID, now, entity.ExpirationDate, err.Error())
			return err
		}
		c.Debugf("DatastoreStore expireSession delete done. session.ID=%s", sessionID)
	}
	return nil
}

// MemcacheStore --------------------------------------------------------------

// NewMemcacheStore returns a new MemcacheStore.
//
// The keyPrefix argument is the prefix used for memcache keys. If empty it
// will use "gorilla.appengine.sessions.".
//
// See NewCookieStore() for a description of the other parameters.
func NewMemcacheStore(keyPrefix string, keyPairs ...[]byte) *MemcacheStore {
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
	}
}

// MemcacheStore stores sessions in the App Engine memcache.
type MemcacheStore struct {
	Codecs  []securecookie.Codec
	Options *sessions.Options // default configuration
	prefix  string
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
	if err := saveToMemcache(c, session); err != nil {
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
func saveToMemcache(c appengine.Context, session *sessions.Session) error {
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
		c.Debugf("MemcacheStore.save. session.ID=%s, expiration=%s",
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
		c.Debugf("MemcacheStore.save. delete session.ID=%s", session.ID)
	}
	return nil
}

// load gets a value from memcache and decodes its content into session.Values.
func loadFromMemcache(c appengine.Context, session *sessions.Session) error {
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
