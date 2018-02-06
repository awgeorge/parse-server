'use strict';

const Parse = require('parse/node');
const request = require('request-promise');

// const Config = require('../src/Config');

const EMAIL = 'foo@bar.com';
const ZIP = '10001';
const SSN = '999-99-9999';
const NICKNAME = 'PublicNickname';

describe('Personally Identifiable Information', () => {
  let user;
  let adminUser;
  let adminRole;

  beforeEach(done => {
    return new Parse.Role("Administrator", new Parse.ACL()).save(null, { useMasterKey: true })
      .then(role => adminRole = role)
      .then(() => Parse.User.signUp('tester', 'abc'))
      .then(loggedInUser => user = loggedInUser)
      .then(() => Parse.User.logIn(user.get('username'), 'abc'))
      .then(() => {
        const managementRole = new Parse.Role("managementOf_user" + user.id, new Parse.ACL(user));
        managementRole.getRoles().add(adminRole);

        return managementRole.save(null, { useMasterKey: true });
      }).then((managementRole) => {
        const userACL = new Parse.ACL();
        userACL.setPublicReadAccess(true);
        userACL.setReadAccess(managementRole, true);
        userACL.setWriteAccess(managementRole, true);

        return user.set('email', EMAIL)
          .set('zip', ZIP)
          .set('ssn', SSN)
          .set('nickname', NICKNAME)
          .setACL(userACL)
          .save()})
      .then(() => done(), (e) => console.log(e));
  });

  it('should be able to get own PII via API with object', (done) => {
    const userObj = new (Parse.Object.extend(Parse.User));
    userObj.id = user.id;
    userObj.fetch().then(
      fetchedUser => {
        expect(fetchedUser.get('email')).toBe(EMAIL);
      }, e => console.error('error', e))
      .done(() => done());
  });

  it('should not be able to get PII via API with object', (done) => {
    Parse.User.logOut()
      .then(() => {
        const userObj = new (Parse.Object.extend(Parse.User));
        userObj.id = user.id;
        userObj.fetch().then(
          fetchedUser => {
            expect(fetchedUser.get('email')).toBe(undefined);
          })
          .fail(e => {
            done.fail(JSON.stringify(e));
          })
          .done(() => done());
      });
  });

  it('should be able to get non PII via API with object', (done) => {
    Parse.User.logOut()
      .then(() => {
        const userObj = new (Parse.Object.extend(Parse.User));
        userObj.id = user.id;
        userObj.fetch().then(
          fetchedUser => {
            expect(fetchedUser.get('nickname')).toBe(NICKNAME);
          })
          .fail(e => {
            done.fail(JSON.stringify(e));
          })
          .done(() => done());
      });
  });

  it('should be able to get PII via API with object using master key', (done) => {
    Parse.User.logOut()
      .then(() => {
        const userObj = new (Parse.Object.extend(Parse.User));
        userObj.id = user.id;
        userObj.fetch({ useMasterKey: true }).then(
          fetchedUser => {
            expect(fetchedUser.get('email')).toBe(EMAIL);
          }, e => console.error('error', e))
          .done(() => done());
      });
  });

  it('should be able to get own PII via API with Find', (done) => {
    new Parse.Query(Parse.User)
      .first()
      .then(fetchedUser => {
        expect(fetchedUser.get('email')).toBe(EMAIL);
        expect(fetchedUser.get('zip')).toBe(ZIP);
        expect(fetchedUser.get('ssn')).toBe(SSN);
        done();
      });
  });

  it('should not get PII via API with Find', (done) => {
    Parse.User.logOut()
      .then(() => new Parse.Query(Parse.User)
        .first()
        .then(fetchedUser => {
          expect(fetchedUser.get('email')).toBe(undefined);
          expect(fetchedUser.get('zip')).toBe(ZIP);
          expect(fetchedUser.get('ssn')).toBe(SSN);
          done();
        })
      );
  });

  it('should get PII via API with Find using master key', (done) => {
    Parse.User.logOut()
      .then(() => new Parse.Query(Parse.User)
        .first({ useMasterKey: true })
        .then(fetchedUser => {
          expect(fetchedUser.get('email')).toBe(EMAIL);
          expect(fetchedUser.get('zip')).toBe(ZIP);
          expect(fetchedUser.get('ssn')).toBe(SSN);
          done();
        })
      );
  });


  it('should be able to get own PII via API with Get', (done) => {
    new Parse.Query(Parse.User)
      .get(user.id)
      .then(fetchedUser => {
        expect(fetchedUser.get('email')).toBe(EMAIL);
        expect(fetchedUser.get('zip')).toBe(ZIP);
        expect(fetchedUser.get('ssn')).toBe(SSN);
        done();
      });
  });

  it('should not get PII via API with Get', (done) => {
    Parse.User.logOut()
      .then(() => new Parse.Query(Parse.User)
        .get(user.id)
        .then(fetchedUser => {
          expect(fetchedUser.get('email')).toBe(undefined);
          expect(fetchedUser.get('zip')).toBe(ZIP);
          expect(fetchedUser.get('ssn')).toBe(SSN);
          done();
        })
      );
  });

  it('should get PII via API with Get using master key', (done) => {
    Parse.User.logOut()
      .then(() => new Parse.Query(Parse.User)
        .get(user.id, { useMasterKey: true })
        .then(fetchedUser => {
          expect(fetchedUser.get('email')).toBe(EMAIL);
          expect(fetchedUser.get('zip')).toBe(ZIP);
          expect(fetchedUser.get('ssn')).toBe(SSN);
          done();
        })
      );
  });

  it('should not get PII via REST', (done) => {
    request.get({
      url: 'http://localhost:8378/1/classes/_User',
      json: true,
      headers: {
        'X-Parse-Application-Id': 'test',
        'X-Parse-Javascript-Key': 'test'
      }
    })
      .then(
        result => {
          const fetchedUser = result.results[0];
          expect(fetchedUser.zip).toBe(ZIP);
          expect(fetchedUser.email).toBe(undefined);
        },
        e => console.error('error', e.message)
      ).done(() => done());
  });

  it('should get PII via REST with self credentials', (done) => {
    request.get({
      url: 'http://localhost:8378/1/classes/_User',
      json: true,
      headers: {
        'X-Parse-Application-Id': 'test',
        'X-Parse-Javascript-Key': 'test',
        'X-Parse-Session-Token': user.getSessionToken()
      }
    })
      .then(
        result => {
          const fetchedUser = result.results[0];
          expect(fetchedUser.zip).toBe(ZIP);
          expect(fetchedUser.email).toBe(EMAIL);
        },
        e => console.error('error', e.message)
      ).done(() => done());
  });

  it('should get PII via REST using master key', (done) => {
    request.get({
      url: 'http://localhost:8378/1/classes/_User',
      json: true,
      headers: {
        'X-Parse-Application-Id': 'test',
        'X-Parse-Master-Key': 'test'
      }
    })
      .then(
        result => {
          const fetchedUser = result.results[0];
          expect(fetchedUser.zip).toBe(ZIP);
          expect(fetchedUser.email).toBe(EMAIL);
        },
        e => console.error('error', e.message)
      ).done(() => done());
  });

  it('should not get PII via REST by ID', (done) => {
    request.get({
      url: `http://localhost:8378/1/classes/_User/${user.id}`,
      json: true,
      headers: {
        'X-Parse-Application-Id': 'test',
        'X-Parse-Javascript-Key': 'test'
      }
    })
      .then(
        result => {
          const fetchedUser = result;
          expect(fetchedUser.zip).toBe(ZIP);
          expect(fetchedUser.email).toBe(undefined);
        },
        e => console.error('error', e.message)
      ).done(() => done());
  });

  it('should get PII via REST by ID  with self credentials', (done) => {
    request.get({
      url: `http://localhost:8378/1/classes/_User/${user.id}`,
      json: true,
      headers: {
        'X-Parse-Application-Id': 'test',
        'X-Parse-Javascript-Key': 'test',
        'X-Parse-Session-Token': user.getSessionToken()
      }
    })
      .then(
        result => {
          const fetchedUser = result;
          expect(fetchedUser.zip).toBe(ZIP);
          expect(fetchedUser.email).toBe(EMAIL);
        },
        e => console.error('error', e.message)
      ).done(() => done());
  });

  it('should get PII via REST by ID with master key', (done) => {
    request.get({
      url: `http://localhost:8378/1/classes/_User/${user.id}`,
      json: true,
      headers: {
        'X-Parse-Application-Id': 'test',
        'X-Parse-Javascript-Key': 'test',
        'X-Parse-Master-Key': 'test',
      }
    })
      .then(
        result => {
          const fetchedUser = result;
          expect(fetchedUser.zip).toBe(ZIP);
          expect(fetchedUser.email).toBe(EMAIL);
        },
        e => console.error('error', e.message)
      ).done(() => done());
  });

  describe('with configured sensitive fields', () => {
    beforeEach((done) => {
      reconfigureServer({ userSensitiveFields: ['ssn', 'zip'] })
        .then(() => done());
    });

    it('should be able to get own PII via API with object', (done) => {
      const userObj = new (Parse.Object.extend(Parse.User));
      userObj.id = user.id;
      userObj.fetch().then(
        fetchedUser => {
          expect(fetchedUser.get('email')).toBe(EMAIL);
          expect(fetchedUser.get('zip')).toBe(ZIP);
          expect(fetchedUser.get('ssn')).toBe(SSN);
          expect(fetchedUser.get('nickname')).toBe(NICKNAME);
          done();
        }, e => done.fail(e));
    });

    it('should not be able to get PII via API with object', (done) => {
      Parse.User.logOut()
        .then(() => {
          const userObj = new (Parse.Object.extend(Parse.User));
          userObj.id = user.id;
          userObj.fetch().then(
            fetchedUser => {
              expect(fetchedUser.get('email')).toBe(undefined);
              expect(fetchedUser.get('zip')).toBe(undefined);
              expect(fetchedUser.get('ssn')).toBe(undefined);
              expect(fetchedUser.get('nickname')).toBe(NICKNAME);
            }, e => console.error('error', e))
            .done(() => done());
        });
    });

    it('should be able to get PII via API with object using master key', (done) => {
      Parse.User.logOut()
        .then(() => {
          const userObj = new (Parse.Object.extend(Parse.User));
          userObj.id = user.id;
          userObj.fetch({ useMasterKey: true }).then(
            fetchedUser => {
              expect(fetchedUser.get('email')).toBe(EMAIL);
              expect(fetchedUser.get('zip')).toBe(ZIP);
              expect(fetchedUser.get('ssn')).toBe(SSN);
              expect(fetchedUser.get('nickname')).toBe(NICKNAME);
            }, e => console.error('error', e))
            .done(() => done());
        });
    });


    it('should be able to get own PII via API with Find', (done) => {
      new Parse.Query(Parse.User)
        .first()
        .then(fetchedUser => {
          expect(fetchedUser.get('email')).toBe(EMAIL);
          expect(fetchedUser.get('zip')).toBe(ZIP);
          expect(fetchedUser.get('ssn')).toBe(SSN);
          expect(fetchedUser.get('nickname')).toBe(NICKNAME);
          done();
        });
    });

    it('should not get PII via API with Find', (done) => {
      Parse.User.logOut()
        .then(() => new Parse.Query(Parse.User)
          .first()
          .then(fetchedUser => {
            expect(fetchedUser.get('email')).toBe(undefined);
            expect(fetchedUser.get('zip')).toBe(undefined);
            expect(fetchedUser.get('ssn')).toBe(undefined);
            expect(fetchedUser.get('nickname')).toBe(NICKNAME);
            done();
          })
        );
    });

    it('should get PII via API with Find using master key', (done) => {
      Parse.User.logOut()
        .then(() => new Parse.Query(Parse.User)
          .first({ useMasterKey: true })
          .then(fetchedUser => {
            expect(fetchedUser.get('email')).toBe(EMAIL);
            expect(fetchedUser.get('zip')).toBe(ZIP);
            expect(fetchedUser.get('ssn')).toBe(SSN);
            expect(fetchedUser.get('nickname')).toBe(NICKNAME);
            done();
          })
        );
    });


    it('should be able to get own PII via API with Get', (done) => {
      new Parse.Query(Parse.User)
        .get(user.id)
        .then(fetchedUser => {
          expect(fetchedUser.get('email')).toBe(EMAIL);
          expect(fetchedUser.get('zip')).toBe(ZIP);
          expect(fetchedUser.get('ssn')).toBe(SSN);
          expect(fetchedUser.get('nickname')).toBe(NICKNAME);
          done();
        });
    });

    it('should not get PII via API with Get', (done) => {
      Parse.User.logOut()
        .then(() => new Parse.Query(Parse.User)
          .get(user.id)
          .then(fetchedUser => {
            expect(fetchedUser.get('email')).toBe(undefined);
            expect(fetchedUser.get('zip')).toBe(undefined);
            expect(fetchedUser.get('ssn')).toBe(undefined);
            expect(fetchedUser.get('nickname')).toBe(NICKNAME);
            done();
          })
        );
    });

    it('should get PII via API with Get using master key', (done) => {
      Parse.User.logOut()
        .then(() => new Parse.Query(Parse.User)
          .get(user.id, { useMasterKey: true })
          .then(fetchedUser => {
            expect(fetchedUser.get('email')).toBe(EMAIL);
            expect(fetchedUser.get('zip')).toBe(ZIP);
            expect(fetchedUser.get('ssn')).toBe(SSN);
            expect(fetchedUser.get('nickname')).toBe(NICKNAME);
            done();
          })
        );
    });

    it('should not get PII via REST', (done) => {
      request.get({
        url: 'http://localhost:8378/1/classes/_User',
        json: true,
        headers: {
          'X-Parse-Application-Id': 'test',
          'X-Parse-Javascript-Key': 'test'
        }
      })
        .then(
          result => {
            const fetchedUser = result.results[0];
            expect(fetchedUser.zip).toBe(undefined);
            expect(fetchedUser.ssn).toBe(undefined);
            expect(fetchedUser.email).toBe(undefined);
            expect(fetchedUser.nickname).toBe(NICKNAME);
          },
          e => console.error('error', e.message)
        ).done(() => done());
    });

    it('should get PII via REST with self credentials', (done) => {
      request.get({
        url: 'http://localhost:8378/1/classes/_User',
        json: true,
        headers: {
          'X-Parse-Application-Id': 'test',
          'X-Parse-Javascript-Key': 'test',
          'X-Parse-Session-Token': user.getSessionToken()
        }
      })
        .then(
          result => {
            const fetchedUser = result.results[0];
            expect(fetchedUser.zip).toBe(ZIP);
            expect(fetchedUser.email).toBe(EMAIL);
            expect(fetchedUser.ssn).toBe(SSN);
            expect(fetchedUser.nickname).toBe(NICKNAME);
          },
          e => console.error('error', e.message)
        ).done(() => done());
    });

    it('should get PII via REST using master key', (done) => {
      request.get({
        url: 'http://localhost:8378/1/classes/_User',
        json: true,
        headers: {
          'X-Parse-Application-Id': 'test',
          'X-Parse-Master-Key': 'test'
        }
      })
        .then(
          result => {
            const fetchedUser = result.results[0];
            expect(fetchedUser.zip).toBe(ZIP);
            expect(fetchedUser.email).toBe(EMAIL);
            expect(fetchedUser.ssn).toBe(SSN);
            expect(fetchedUser.nickname).toBe(NICKNAME);
          },
          e => console.error('error', e.message)
        ).done(() => done());
    });

    it('should not get PII via REST by ID', (done) => {
      request.get({
        url: `http://localhost:8378/1/classes/_User/${user.id}`,
        json: true,
        headers: {
          'X-Parse-Application-Id': 'test',
          'X-Parse-Javascript-Key': 'test'
        }
      })
        .then(
          result => {
            const fetchedUser = result;
            expect(fetchedUser.zip).toBe(undefined);
            expect(fetchedUser.email).toBe(undefined);
            expect(fetchedUser.nickname).toBe(NICKNAME);
          },
          e => console.error('error', e.message)
        ).done(() => done());
    });

    it('should get PII via REST by ID  with self credentials', (done) => {
      request.get({
        url: `http://localhost:8378/1/classes/_User/${user.id}`,
        json: true,
        headers: {
          'X-Parse-Application-Id': 'test',
          'X-Parse-Javascript-Key': 'test',
          'X-Parse-Session-Token': user.getSessionToken()
        }
      })
        .then(
          result => {
            const fetchedUser = result;
            expect(fetchedUser.zip).toBe(ZIP);
            expect(fetchedUser.email).toBe(EMAIL);
            expect(fetchedUser.nickname).toBe(NICKNAME);
          },
          e => console.error('error', e.message)
        ).done(() => done());
    });

    it('should get PII via REST by ID  with master key', (done) => {
      request.get({
        url: `http://localhost:8378/1/classes/_User/${user.id}`,
        json: true,
        headers: {
          'X-Parse-Application-Id': 'test',
          'X-Parse-Javascript-Key': 'test',
          'X-Parse-Master-Key': 'test',
        }
      })
        .then(
          result => {
            const fetchedUser = result;
            expect(fetchedUser.zip).toBe(ZIP);
            expect(fetchedUser.email).toBe(EMAIL);
            expect(fetchedUser.nickname).toBe(NICKNAME);
          },
          e => console.error('error', e.message)
        ).done(() => done());
    });
  });

  describe('with privilaged user', () => {
    beforeEach((done) => {
      return Parse.User.logOut()
        .then(() => Parse.User.signUp('administrator', 'secure'))
        .then(loggedInUser => adminUser = loggedInUser)
        .then(() => Parse.User.logIn(adminUser.get('username'), 'secure'))
        .then(() => adminRole.getUsers().add(adminUser).save(null, {useMasterKey: true}))
        .then(() => done());
    });

    it('admin should be able to get user PII via API with object', (done) => {
      const userObj = new (Parse.Object.extend(Parse.User));
      userObj.id = user.id;
      userObj.fetch().then(
        fetchedUser => {
          expect(fetchedUser.get('email')).toBe(EMAIL);
        }, e => console.error('error', e))
        .done(() => done());
    });

    it('admin should be able to get user PII via API with Find', (done) => {
      new Parse.Query(Parse.User)
        .first()
        .then(fetchedUser => {
          expect(fetchedUser.get('email')).toBe(EMAIL);
          expect(fetchedUser.get('zip')).toBe(ZIP);
          expect(fetchedUser.get('ssn')).toBe(SSN);
          done();
        });
    });

    it('admin should be able to get user PII via API with Get', (done) => {
      new Parse.Query(Parse.User)
        .get(user.id)
        .then(fetchedUser => {
          expect(fetchedUser.get('email')).toBe(EMAIL);
          expect(fetchedUser.get('zip')).toBe(ZIP);
          expect(fetchedUser.get('ssn')).toBe(SSN);
          expect(fetchedUser.get('nickname')).toBe(NICKNAME);
          done();
        });
    });

    it('admin should get PII via REST with admin credentials', (done) => {
      request.get({
        url: 'http://localhost:8378/1/classes/_User',
        json: true,
        headers: {
          'X-Parse-Application-Id': 'test',
          'X-Parse-Javascript-Key': 'test',
          'X-Parse-Session-Token': adminUser.getSessionToken()
        }
      })
        .then(
          result => {
            const fetchedUser = result.results[0];
            expect(fetchedUser.zip).toBe(ZIP);
            expect(fetchedUser.email).toBe(EMAIL);
          },
          e => console.error('error', e.message)
        ).done(() => done());
    });

  });
});
