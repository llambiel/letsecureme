'use strict';

var gulp = require('gulp');
var sass = require('gulp-sass');
var imagemin = require('gulp-imagemin');
var exec = require('child_process').exec;

gulp.task('sass', function() {
    return gulp.src('./src/scss/style.scss')
        .pipe(sass({
            outputStyle: 'compressed',
            includePaths: [
                './node_modules/susy/sass',
                './node_modules/breakpoint-sass/stylesheets/',
                './node_modules/',
            ],
        }).on('error', sass.logError))
        .pipe(gulp.dest('./dist/static/css/'));
});

gulp.task('imagemin', function() {
    return gulp.src(['./src/svg/*', './src/img/*'])
        .pipe(imagemin({
            progressive: true,
            svgoPlugins: [
                {removeViewBox: false},
                {cleanupIDs: false},
            ],
        }))
        .pipe(gulp.dest('./dist/static/images/'));
});

gulp.task('render', function() {
    exec('node ./render.js', function() {
        console.log(arguments);
    });
});

gulp.task('watch', function() {
    gulp.watch('./src/scss/**/*.scss', ['sass']);
    gulp.watch('./src/post.md', ['render']);
});

gulp.task('default', ['render', 'sass', 'imagemin']);


