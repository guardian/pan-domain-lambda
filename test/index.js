'use strict'; //eslint-disable-line strict

const tap = require('tap');
const lambda = require('../tmp/lambda/index');

tap.test('fails when panda verify fails', test => {
	test.plan(3);

	lambda.handleEvents({
		events: { authorizationToken: 'gutoolsAuth-assym=base64.signature' },
		panda: {
			verify: () => Promise.reject(new Error('a failure in test')),
			stop: () => {}
		},
		logger: {
			log () {},
			error (err) {
				test.type(err, Error);
				test.equal(err.message, 'a failure in test');
			}
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
		panda: {
			verify: () => Promise.resolve({
				status: 'Authorised',
				user: {
					firstName: 'Jon',
					lastName: 'Doe',
					email: 'someone@guardian.co.uk'
				}
			}),
			stop: () => {}
		},
		logger: {
			log () {},
			error () {}
		},
		callback: (err, policy) => {
			test.equal(policy.principalId, 'Jon Doe <someone@guardian.co.uk>');
			test.equal(policy.policyDocument.Statement[0].Effect, 'Allow');
			test.end();
		}
	});
});
