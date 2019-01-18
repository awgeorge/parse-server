'use strict';

const Parse = require('parse/node');
const request = require('../lib/request');

// const Config = require('../lib/Config');

const EMAIL = 'foo@bar.com';
const ZIP = '10001';
const SSN = '999-99-9999';

describe('Personally Identifiable Information', () => {
  let user;

  beforeEach(done => {
    return Parse.User.signUp('tester', 'abc')
      .then(loggedInUser => (user = loggedInUser))
      .then(() => Parse.User.logIn(user.get('username'), 'abc'))
      .then(() =>
        user
          .set('email', EMAIL)
          .set('zip', ZIP)
          .set('ssn', SSN)
          .save()
      )
      .then(() => done());
  });

  it('should be able to get own PII via API with object', done => {
    const userObj = new (Parse.Object.extend(Parse.User))();
    userObj.id = user.id;
    userObj
      .fetch()
      .then(
        fetchedUser => {
          expect(fetchedUser.get('email')).toBe(EMAIL);
        },
        e => console.error('error', e)
      )
      .then(done)
      .catch(done.fail);
  });

  it('should not be able to get PII via API with object', done => {
    Parse.User.logOut().then(() => {
      const userObj = new (Parse.Object.extend(Parse.User))();
      userObj.id = user.id;
      userObj
        .fetch()
        .then(fetchedUser => {
          expect(fetchedUser.get('email')).toBe(undefined);
          done();
        })
        .catch(e => {
          done.fail(JSON.stringify(e));
        })
        .then(done)
        .catch(done.fail);
    });
  });

  it('should be able to get PII via API with object using master key', done => {
    Parse.User.logOut().then(() => {
      const userObj = new (Parse.Object.extend(Parse.User))();
      userObj.id = user.id;
      userObj
        .fetch({ useMasterKey: true })
        .then(
          fetchedUser => {
            expect(fetchedUser.get('email')).toBe(EMAIL);
          },
          e => console.error('error', e)
        )
        .then(done)
        .catch(done.fail);
    });
  });

  it('should be able to get own PII via API with Find', done => {
    new Parse.Query(Parse.User).first().then(fetchedUser => {
      expect(fetchedUser.get('email')).toBe(EMAIL);
      expect(fetchedUser.get('zip')).toBe(ZIP);
      expect(fetchedUser.get('ssn')).toBe(SSN);
      done();
    });
  });

  it('should not get PII via API with Find', done => {
    Parse.User.logOut().then(() =>
      new Parse.Query(Parse.User).first().then(fetchedUser => {
        expect(fetchedUser.get('email')).toBe(undefined);
        expect(fetchedUser.get('zip')).toBe(ZIP);
        expect(fetchedUser.get('ssn')).toBe(SSN);
        done();
      })
    );
  });

  it('should get PII via API with Find using master key', done => {
    Parse.User.logOut().then(() =>
      new Parse.Query(Parse.User)
        .first({ useMasterKey: true })
        .then(fetchedUser => {
          expect(fetchedUser.get('email')).toBe(EMAIL);
          expect(fetchedUser.get('zip')).toBe(ZIP);
          expect(fetchedUser.get('ssn')).toBe(SSN);
          done();
        })
    );
  });

  it('should be able to get own PII via API with Get', done => {
    new Parse.Query(Parse.User).get(user.id).then(fetchedUser => {
      expect(fetchedUser.get('email')).toBe(EMAIL);
      expect(fetchedUser.get('zip')).toBe(ZIP);
      expect(fetchedUser.get('ssn')).toBe(SSN);
      done();
    });
  });

  it('should not get PII via API with Get', done => {
    Parse.User.logOut().then(() =>
      new Parse.Query(Parse.User).get(user.id).then(fetchedUser => {
        expect(fetchedUser.get('email')).toBe(undefined);
        expect(fetchedUser.get('zip')).toBe(ZIP);
        expect(fetchedUser.get('ssn')).toBe(SSN);
        done();
      })
    );
  });

  it('should get PII via API with Get using master key', done => {
    Parse.User.logOut().then(() =>
      new Parse.Query(Parse.User)
        .get(user.id, { useMasterKey: true })
        .then(fetchedUser => {
          expect(fetchedUser.get('email')).toBe(EMAIL);
          expect(fetchedUser.get('zip')).toBe(ZIP);
          expect(fetchedUser.get('ssn')).toBe(SSN);
          done();
        })
    );
  });

  it('should not get PII via REST', done => {
    request({
      url: 'http://localhost:8378/1/classes/_User',
      headers: {
        'X-Parse-Application-Id': 'test',
        'X-Parse-Javascript-Key': 'test',
      },
    })
      .then(
        response => {
          const result = response.data;
          const fetchedUser = result.results[0];
          expect(fetchedUser.zip).toBe(ZIP);
          expect(fetchedUser.email).toBe(undefined);
        },
        e => console.error('error', e.message)
      )
      .then(done)
      .catch(done.fail);
  });

  it('should get PII via REST with self credentials', done => {
    request({
      url: 'http://localhost:8378/1/classes/_User',
      json: true,
      headers: {
        'X-Parse-Application-Id': 'test',
        'X-Parse-Javascript-Key': 'test',
        'X-Parse-Session-Token': user.getSessionToken(),
      },
    })
      .then(
        response => {
          const result = response.data;
          const fetchedUser = result.results[0];
          expect(fetchedUser.zip).toBe(ZIP);
          expect(fetchedUser.email).toBe(EMAIL);
        },
        e => console.error('error', e.message)
      )
      .then(done);
  });

  it('should get PII via REST using master key', done => {
    request({
      url: 'http://localhost:8378/1/classes/_User',
      json: true,
      headers: {
        'X-Parse-Application-Id': 'test',
        'X-Parse-Master-Key': 'test',
      },
    })
      .then(
        response => {
          const result = response.data;
          const fetchedUser = result.results[0];
          expect(fetchedUser.zip).toBe(ZIP);
          expect(fetchedUser.email).toBe(EMAIL);
        },
        e => console.error('error', e.message)
      )
      .then(() => done());
  });

  it('should not get PII via REST by ID', done => {
    request({
      url: `http://localhost:8378/1/classes/_User/${user.id}`,
      headers: {
        'X-Parse-Application-Id': 'test',
        'X-Parse-Javascript-Key': 'test',
      },
    })
      .then(
        response => {
          const fetchedUser = response.data;
          expect(fetchedUser.zip).toBe(ZIP);
          expect(fetchedUser.email).toBe(undefined);
        },
        e => done.fail(e)
      )
      .then(() => done());
  });

  it('should get PII via REST by ID  with self credentials', done => {
    request({
      url: `http://localhost:8378/1/classes/_User/${user.id}`,
      json: true,
      headers: {
        'X-Parse-Application-Id': 'test',
        'X-Parse-Javascript-Key': 'test',
        'X-Parse-Session-Token': user.getSessionToken(),
      },
    })
      .then(
        response => {
          const result = response.data;
          const fetchedUser = result;
          expect(fetchedUser.zip).toBe(ZIP);
          expect(fetchedUser.email).toBe(EMAIL);
        },
        e => console.error('error', e.message)
      )
      .then(() => done());
  });

  it('should get PII via REST by ID  with master key', done => {
    request({
      url: `http://localhost:8378/1/classes/_User/${user.id}`,
      json: true,
      headers: {
        'X-Parse-Application-Id': 'test',
        'X-Parse-Javascript-Key': 'test',
        'X-Parse-Master-Key': 'test',
      },
    })
      .then(
        response => {
          const result = response.data;
          const fetchedUser = result;
          expect(fetchedUser.zip).toBe(ZIP);
          expect(fetchedUser.email).toBe(EMAIL);
        },
        e => console.error('error', e.message)
      )
      .then(() => done());
  });

  describe('with configured sensitive fields', () => {
    beforeEach(done => {
      reconfigureServer({ userSensitiveFields: ['ssn', 'zip'] }).then(() =>
        done()
      );
    });

    it('should be able to get own PII via API with object', done => {
      const userObj = new (Parse.Object.extend(Parse.User))();
      userObj.id = user.id;
      userObj.fetch().then(
        fetchedUser => {
          expect(fetchedUser.get('email')).toBe(EMAIL);
          expect(fetchedUser.get('zip')).toBe(ZIP);
          expect(fetchedUser.get('ssn')).toBe(SSN);
          done();
        },
        e => done.fail(e)
      );
    });

    it('should not be able to get PII via API with object', done => {
      Parse.User.logOut().then(() => {
        const userObj = new (Parse.Object.extend(Parse.User))();
        userObj.id = user.id;
        userObj
          .fetch()
          .then(
            fetchedUser => {
              expect(fetchedUser.get('email')).toBe(undefined);
              expect(fetchedUser.get('zip')).toBe(undefined);
              expect(fetchedUser.get('ssn')).toBe(undefined);
            },
            e => console.error('error', e)
          )
          .then(done)
          .catch(done.fail);
      });
    });

    it('should be able to get PII via API with object using master key', done => {
      Parse.User.logOut().then(() => {
        const userObj = new (Parse.Object.extend(Parse.User))();
        userObj.id = user.id;
        userObj
          .fetch({ useMasterKey: true })
          .then(fetchedUser => {
            expect(fetchedUser.get('email')).toBe(EMAIL);
            expect(fetchedUser.get('zip')).toBe(ZIP);
            expect(fetchedUser.get('ssn')).toBe(SSN);
          }, done.fail)
          .then(done)
          .catch(done.fail);
      });
    });

    it('should be able to get own PII via API with Find', done => {
      new Parse.Query(Parse.User).first().then(fetchedUser => {
        expect(fetchedUser.get('email')).toBe(EMAIL);
        expect(fetchedUser.get('zip')).toBe(ZIP);
        expect(fetchedUser.get('ssn')).toBe(SSN);
        done();
      });
    });

    it('should not get PII via API with Find', done => {
      Parse.User.logOut().then(() =>
        new Parse.Query(Parse.User).first().then(fetchedUser => {
          expect(fetchedUser.get('email')).toBe(undefined);
          expect(fetchedUser.get('zip')).toBe(undefined);
          expect(fetchedUser.get('ssn')).toBe(undefined);
          done();
        })
      );
    });

    it('should get PII via API with Find using master key', done => {
      Parse.User.logOut().then(() =>
        new Parse.Query(Parse.User)
          .first({ useMasterKey: true })
          .then(fetchedUser => {
            expect(fetchedUser.get('email')).toBe(EMAIL);
            expect(fetchedUser.get('zip')).toBe(ZIP);
            expect(fetchedUser.get('ssn')).toBe(SSN);
            done();
          })
      );
    });

    it('should be able to get own PII via API with Get', done => {
      new Parse.Query(Parse.User).get(user.id).then(fetchedUser => {
        expect(fetchedUser.get('email')).toBe(EMAIL);
        expect(fetchedUser.get('zip')).toBe(ZIP);
        expect(fetchedUser.get('ssn')).toBe(SSN);
        done();
      });
    });

    it('should not get PII via API with Get', done => {
      Parse.User.logOut().then(() =>
        new Parse.Query(Parse.User).get(user.id).then(fetchedUser => {
          expect(fetchedUser.get('email')).toBe(undefined);
          expect(fetchedUser.get('zip')).toBe(undefined);
          expect(fetchedUser.get('ssn')).toBe(undefined);
          done();
        })
      );
    });

    it('should get PII via API with Get using master key', done => {
      Parse.User.logOut().then(() =>
        new Parse.Query(Parse.User)
          .get(user.id, { useMasterKey: true })
          .then(fetchedUser => {
            expect(fetchedUser.get('email')).toBe(EMAIL);
            expect(fetchedUser.get('zip')).toBe(ZIP);
            expect(fetchedUser.get('ssn')).toBe(SSN);
            done();
          })
      );
    });

    it('should not get PII via REST', done => {
      request({
        url: 'http://localhost:8378/1/classes/_User',
        headers: {
          'X-Parse-Application-Id': 'test',
          'X-Parse-Javascript-Key': 'test',
        },
      })
        .then(response => {
          const result = response.data;
          const fetchedUser = result.results[0];
          expect(fetchedUser.zip).toBe(undefined);
          expect(fetchedUser.ssn).toBe(undefined);
          expect(fetchedUser.email).toBe(undefined);
        }, done.fail)
        .then(done)
        .catch(done.fail);
    });

    it('should get PII via REST with self credentials', done => {
      request({
        url: 'http://localhost:8378/1/classes/_User',
        json: true,
        headers: {
          'X-Parse-Application-Id': 'test',
          'X-Parse-Javascript-Key': 'test',
          'X-Parse-Session-Token': user.getSessionToken(),
        },
      })
        .then(
          response => {
            const result = response.data;
            const fetchedUser = result.results[0];
            expect(fetchedUser.zip).toBe(ZIP);
            expect(fetchedUser.email).toBe(EMAIL);
            expect(fetchedUser.ssn).toBe(SSN);
          },
          () => {}
        )
        .then(done)
        .catch(done.fail);
    });

    it('should get PII via REST using master key', done => {
      request({
        url: 'http://localhost:8378/1/classes/_User',
        json: true,
        headers: {
          'X-Parse-Application-Id': 'test',
          'X-Parse-Master-Key': 'test',
        },
      })
        .then(
          response => {
            const result = response.data;
            const fetchedUser = result.results[0];
            expect(fetchedUser.zip).toBe(ZIP);
            expect(fetchedUser.email).toBe(EMAIL);
            expect(fetchedUser.ssn).toBe(SSN);
          },
          e => done.fail(e.data)
        )
        .then(done)
        .catch(done.fail);
    });

    it('should not get PII via REST by ID', done => {
      request({
        url: `http://localhost:8378/1/classes/_User/${user.id}`,
        json: true,
        headers: {
          'X-Parse-Application-Id': 'test',
          'X-Parse-Javascript-Key': 'test',
        },
      })
        .then(
          response => {
            const fetchedUser = response.data;
            expect(fetchedUser.zip).toBe(undefined);
            expect(fetchedUser.email).toBe(undefined);
          },
          e => done.fail(e.data)
        )
        .then(done)
        .catch(done.fail);
    });

    it('should get PII via REST by ID  with self credentials', done => {
      request({
        url: `http://localhost:8378/1/classes/_User/${user.id}`,
        json: true,
        headers: {
          'X-Parse-Application-Id': 'test',
          'X-Parse-Javascript-Key': 'test',
          'X-Parse-Session-Token': user.getSessionToken(),
        },
      })
        .then(
          response => {
            const fetchedUser = response.data;
            expect(fetchedUser.zip).toBe(ZIP);
            expect(fetchedUser.email).toBe(EMAIL);
          },
          () => {}
        )
        .then(done)
        .catch(done.fail);
    });

    it('should get PII via REST by ID  with master key', done => {
      request({
        url: `http://localhost:8378/1/classes/_User/${user.id}`,
        headers: {
          'X-Parse-Application-Id': 'test',
          'X-Parse-Javascript-Key': 'test',
          'X-Parse-Master-Key': 'test',
        },
      })
        .then(
          response => {
            const result = response.data;
            const fetchedUser = result;
            expect(fetchedUser.zip).toBe(ZIP);
            expect(fetchedUser.email).toBe(EMAIL);
          },
          e => done.fail(e.data)
        )
        .then(done)
        .catch(done.fail);
    });

    // Explict ACL should be able to read sensitive information
    describe('with privilaged user', () => {
      let adminUser;

      beforeEach(async done => {
        const adminRole = await new Parse.Role(
          'Administrator',
          new Parse.ACL()
        ).save(null, { useMasterKey: true });

        const managementRole = new Parse.Role(
          'managementOf_user' + user.id,
          new Parse.ACL(user)
        );
        managementRole.getRoles().add(adminRole);
        await managementRole.save(null, { useMasterKey: true });

        const userACL = new Parse.ACL();
        userACL.setReadAccess(managementRole, true);
        await user.setACL(userACL).save(null, { useMasterKey: true });

        adminUser = await Parse.User.signUp('administrator', 'secure');
        adminUser = await Parse.User.logIn(adminUser.get('username'), 'secure');
        await adminRole
          .getUsers()
          .add(adminUser)
          .save(null, { useMasterKey: true });

        done();
      });

      it('privilaged user should be able to get user PII via API with object', done => {
        const userObj = new (Parse.Object.extend(Parse.User))();
        userObj.id = user.id;
        userObj
          .fetch()
          .then(
            fetchedUser => {
              expect(fetchedUser.get('email')).toBe(EMAIL);
            },
            e => console.error('error', e)
          )
          .then(done)
          .catch(done.fail);
      });

      it('privilaged user should be able to get user PII via API with Find', done => {
        new Parse.Query(Parse.User)
          .equalTo('objectId', user.id)
          .find()
          .then(fetchedUser => {
            expect(fetchedUser.get('email')).toBe(EMAIL);
            expect(fetchedUser.get('zip')).toBe(ZIP);
            expect(fetchedUser.get('ssn')).toBe(SSN);
            done();
          });
      });

      it('privilaged user should be able to get user PII via API with Get', done => {
        new Parse.Query(Parse.User).get(user.id).then(fetchedUser => {
          expect(fetchedUser.get('email')).toBe(EMAIL);
          expect(fetchedUser.get('zip')).toBe(ZIP);
          expect(fetchedUser.get('ssn')).toBe(SSN);
          done();
        });
      });

      it('privilaged user should get user PII via REST by ID', done => {
        request({
          url: `http://localhost:8378/1/classes/_User/${user.id}`,
          json: true,
          headers: {
            'X-Parse-Application-Id': 'test',
            'X-Parse-Javascript-Key': 'test',
            'X-Parse-Session-Token': adminUser.getSessionToken(),
          },
        })
          .then(
            response => {
              const result = response.data;
              const fetchedUser = result;
              expect(fetchedUser.zip).toBe(ZIP);
              expect(fetchedUser.email).toBe(EMAIL);
            },
            e => console.error('error', e.message)
          )
          .then(() => done());
      });
    });

    // Public access ACL should always hide sensitive information
    describe('with public read ACL', () => {
      beforeEach(async done => {
        const userACL = new Parse.ACL();
        userACL.setPublicReadAccess();
        await user.setACL(userACL).save(null, { useMasterKey: true });
        done();
      });

      it('should not be able to get user PII via API with object', done => {
        Parse.User.logOut().then(() => {
          const userObj = new (Parse.Object.extend(Parse.User))();
          userObj.id = user.id;
          userObj
            .fetch()
            .then(
              fetchedUser => {
                expect(fetchedUser.get('email')).toBe(undefined);
              },
              e => console.error('error', e)
            )
            .then(done)
            .catch(done.fail);
        });
      });

      it('should not be able to get user PII via API with Find', done => {
        Parse.User.logOut().then(() =>
          new Parse.Query(Parse.User)
            .equalTo('objectId', user.id)
            .find()
            .then(fetchedUser => {
              expect(fetchedUser.get('email')).toBe(undefined);
              expect(fetchedUser.get('zip')).toBe(undefined);
              expect(fetchedUser.get('ssn')).toBe(undefined);
              done();
            })
        );
      });

      it('should not be able to get user PII via API with Get', done => {
        Parse.User.logOut().then(() =>
          new Parse.Query(Parse.User).get(user.id).then(fetchedUser => {
            expect(fetchedUser.get('email')).toBe(undefined);
            expect(fetchedUser.get('zip')).toBe(undefined);
            expect(fetchedUser.get('ssn')).toBe(undefined);
            done();
          })
        );
      });

      it('should not get user PII via REST by ID', done => {
        request({
          url: `http://localhost:8378/1/classes/_User/${user.id}`,
          json: true,
          headers: {
            'X-Parse-Application-Id': 'test',
            'X-Parse-Javascript-Key': 'test',
          },
        })
          .then(
            response => {
              const result = response.data;
              const fetchedUser = result;
              expect(fetchedUser.zip).toBe(undefined);
              expect(fetchedUser.email).toBe(undefined);
            },
            e => console.error('error', e.message)
          )
          .then(() => done());
      });

      // Even with an authenticated user, Public read ACL should never expose sensitive data.
      describe('with another authenticated user', () => {
        let anotherUser;

        beforeEach(async done => {
          return Parse.User.signUp('another', 'abc')
            .then(loggedInUser => (anotherUser = loggedInUser))
            .then(() => Parse.User.logIn(anotherUser.get('username'), 'abc'))
            .then(() => done());
        });

        it('should not be able to get user PII via API with object', done => {
          const userObj = new (Parse.Object.extend(Parse.User))();
          userObj.id = user.id;
          userObj
            .fetch()
            .then(
              fetchedUser => {
                expect(fetchedUser.get('email')).toBe(undefined);
              },
              e => console.error('error', e)
            )
            .then(done)
            .catch(done.fail);
        });

        it('should not be able to get user PII via API with Find', done => {
          new Parse.Query(Parse.User)
            .equalTo('objectId', user.id)
            .find()
            .then(fetchedUser => {
              expect(fetchedUser.get('email')).toBe(undefined);
              expect(fetchedUser.get('zip')).toBe(undefined);
              expect(fetchedUser.get('ssn')).toBe(undefined);
              done();
            });
        });

        it('should not be able to get user PII via API with Get', done => {
          new Parse.Query(Parse.User).get(user.id).then(fetchedUser => {
            expect(fetchedUser.get('email')).toBe(undefined);
            expect(fetchedUser.get('zip')).toBe(undefined);
            expect(fetchedUser.get('ssn')).toBe(undefined);
            done();
          });
        });
      });
    });
  });
});
