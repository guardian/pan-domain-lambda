import nodeResolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

export default {
	input: 'src/index.js',
	plugins: [
		nodeResolve({ jsnext: true }),
		commonjs()
	],
	output: {
		format: 'cjs',
		file: 'tmp/lambda/index.js'
	},
	external: ['aws-sdk']
};
