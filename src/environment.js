const stage = (process.env.AWS_LAMBDA_FUNCTION_NAME || '')
	.split('-')
	.filter(token => /(CODE?|PROD?)/.test(token))
	.pop();

export const STAGE = stage || 'UNKNOWN';
