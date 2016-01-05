global.expect = require('chai').expect;
global._ = require('lodash');
global.Promise = require('bluebird');

var gulp = require("gulp");
var mocha = require('gulp-mocha');

gulp.src('build/**/*.test.js', {
		read: false
	})
	.pipe(mocha());