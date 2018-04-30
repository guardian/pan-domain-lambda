var gulp = require('gulp');
var exec  = require('exec-chainable');
var eslint = require('gulp-eslint');
var path = require('path');
process.env.ARTEFACT_PATH = __dirname;
var riffraff = require('node-riffraff-artefact');

var LAMBDA_SOURCE = 'src/*.js';

gulp.task('compile', function () {
	return exec('rollup -c rollup.config.js');
});

gulp.task('compile-dev', ['compile'], function () {
	gulp.watch(LAMBDA_SOURCE, ['compile']);
});

gulp.task('lint', function () {
	return gulp.src([
		LAMBDA_SOURCE,
		'test/**/*.js'
	])
	.pipe(eslint())
	.pipe(eslint.formatEach('compact', process.stderr))
	.pipe(eslint.failAfterError());
});

gulp.task('lint-dev', ['lint'], function () {
	gulp.watch(LAMBDA_SOURCE, ['lint']);
});

gulp.task('compile', function () {
	return exec('rollup -c rollup.config.js');
});

gulp.task('deploy', ['compile'], function (cb) {

	riffraff.s3FilesUpload().then(function () {
		cb();
	}).catch(function (error) {
		cb(error);
	});
});
