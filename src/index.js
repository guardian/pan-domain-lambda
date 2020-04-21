import {guardianValidation, PanDomainAuthentication} from '@guardian/pan-domain-node'; 
import {SETTINGS_FILE, REGION} from './environment';

export function handler (events, context, callback) {
	const panda = new PanDomainAuthentication('gutoolsAuth-assym', REGION, 'pan-domain-auth-settings', SETTINGS_FILE, guardianValidation);
	handleEvents({events, callback, panda, logger: console});
}

export function handleEvents ({events, callback, panda, logger}) {
	const cookie = events.authorizationToken || '';

	panda.verify(cookie)
	.then(({ status, user }) => {
		if (status === 'Authorised') {
			// TODO MRB: remove once @guardian/pan-domain-node supports an API not including the refresher
			panda.stop();

			callback(null, policy(
				`${user.firstName} ${user.lastName} <${user.email}>`,
				'Allow',
				events.methodArn
			));
		} else {
			throw new Error('Authorisation failed ' + status);
		}
	})
	.catch(ex => {
		logger.error(ex);

		// TODO MRB: remove once @guardian/pan-domain-node supports an API not including the refresher
		panda.stop();
		callback(null, policy('', 'Deny', events.methodArn));
	});
}

function policy (principal, effect, arn) {
	return {
		principalId: principal,
		policyDocument: {
			Version: '2012-10-17',
			Statement: [{
				Action: 'execute-api:Invoke',
				Effect: effect,
				Resource: arn
			}]
		}
	};
}
