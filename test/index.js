'use strict'; //eslint-disable-line strict

const tap = require('tap');
const lambda = require('../tmp/lambda/index');
const EventEmitter = require('events');

class EmitterError extends EventEmitter {
	constructor () {
		super();
		process.nextTick(() => this.emit('error', 'emitting an error'));
	}
}
class EmitterResponse extends EventEmitter {
	constructor () {
		super();
		this.statusCode = 200;
		process.nextTick(() => {
			this.emit('data', 'publicKey=abcde');
			this.emit('end');
		});
	}
}

tap.test('fails when fetching a key emits an error', test => {
	test.plan(3);

	lambda.handleEvents({
		events: {},
		https: {
			get (path, callback) {
				callback(new EmitterError());
			}
		},
		logger: {
			log () {},
			error (err) {
				test.type(err, Error);
				test.equal(err.message, 'emitting an error');
			}
		},
		callback: (err, policy) => {
			test.equal(policy.policyDocument.Statement[0].Effect, 'Deny');
			test.end();
		}
	});
});

tap.test('fails when the cookie is not set', function (test) {
	test.plan(5);

	lambda.handleEvents({
		events: {},
		https: {
			get (path, callback) {
				callback(new EmitterResponse());
			}
		},
		logger: {
			log () {},
			error (err) {
				test.type(err, Error);
				test.match(err.message, /fail validation/i);
			}
		},
		validate (cookie, key) {
			test.equal(cookie, '');
			test.match(key, /BEGIN PUBLIC KEY[\s\S]*abcde/i);
			return Promise.reject(new Error('fail validation'));
		},
		callback: (err, policy) => {
			test.equal(policy.policyDocument.Statement[0].Effect, 'Deny');
			test.end();
		}
	});
});

tap.test('fails validating a cookie', function (test) {
	test.plan(4);

	lambda.handleEvents({
		events: { authorizationToken: 'gutoolsAuth-assym=base64.signature' },
		https: {
			get (path, callback) {
				callback(new EmitterResponse());
			}
		},
		logger: {
			log () {},
			error (err) {
				test.type(err, Error);
				test.match(err.message, /fail validation/i);
			}
		},
		validate (cookie) {
			test.equal(cookie, 'base64.signature');
			return Promise.reject(new Error('fail validation'));
		},
		callback: (err, policy) => {
			test.equal(policy.policyDocument.Statement[0].Effect, 'Deny');
			test.end();
		}
	});
});

tap.test('validates the user correctly', function (test) {
	test.plan(2);

	lambda.handleEvents({
		events: { authorizationToken: 'gutoolsAuth-assym=base64.signature' },
		https: {
			get (path, callback) {
				callback(new EmitterResponse());
			}
		},
		logger: {
			log () {},
			error () {}
		},
		validate () {
			return Promise.resolve({
				firstName: 'Jon',
				lastName: 'Doe',
				email: 'someone@guardian.co.uk'
			});
		},
		callback: (err, policy) => {
			test.equal(policy.principalId, 'Jon Doe <someone@guardian.co.uk>');
			test.equal(policy.policyDocument.Statement[0].Effect, 'Allow');
			test.end();
		}
	});
});
