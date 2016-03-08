'use strict';

var gulp = require('gulp');
var sass = require('gulp-sass');
var imagemin = require('gulp-imagemin');
var exec = require('child_process').exec;
var copy = require('gulp-copy');
var concat = require('gulp-concat');

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

gulp.task('fonts', function() {
    return gulp.src('./src/fonts/*')
        .pipe(copy('dist/static/fonts/', {prefix: 2}));
});

gulp.task('ga', function() {
    return gulp.src('./src/js/ga.js')
        .pipe(copy('dist/static/js/', {prefix: 2}));
});

gulp.task('js', function() {
    return gulp.src([
        './node_modules/jquery/dist/jquery.slim.min.js',
        './node_modules/magnific-popup/dist/jquery.magnific-popup.min.js',
        './src/js/base.js',
    ])
    .pipe(concat('script.js'))
    .pipe(gulp.dest('./dist/static/js/'));
});

gulp.task('render', function() {
    exec('node ./render.js', function() {});
});

gulp.task('copy_demo', ['sass', 'imagemin', 'fonts', 'js'], function() {
    gulp.src('./dist/static/css/*')
        .pipe(copy('demo/static/css/', {prefix: 3}));
    gulp.src('./dist/static/js/script.js')
        .pipe(copy('demo/static/js/', {prefix: 3}));
    gulp.src('./dist/static/fonts/*')
        .pipe(copy('demo/static/fonts', {prefix: 3}));
    gulp.src('./dist/static/images/*')
        .pipe(copy('demo/static/images', {prefix: 3}));
});

gulp.task('watch', function() {
    gulp.watch('./src/scss/**/*.scss', ['sass']);
    gulp.watch('./post.md', ['render']);
    gulp.watch(['./src/svg/*', './src/img/*'], ['imagemin']);
});

gulp.task('default', ['render', 'sass', 'js', 'imagemin', 'fonts', 'ga', 'copy_demo']);
