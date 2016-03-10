'use strict';

var gulp = require('gulp');

var concat = require('gulp-concat');
var copy = require('gulp-copy');
var imagemin = require('gulp-imagemin');
var minifyCSS = require('gulp-minify-css');
var rename = require('gulp-rename');
var sass = require('gulp-sass');
var uglify = require('gulp-uglify');


gulp.task('sass', function() {
    return gulp.src('./assets/scss/style.scss')
        .pipe(sass({
            outputStyle: 'compressed',
            includePaths: [
                './node_modules/susy/sass',
                './node_modules/breakpoint-sass/stylesheets/',
                './node_modules/',
            ],
        }).on('error', sass.logError))
        .pipe(rename('all.min.css'))
        .pipe(minifyCSS())
        .pipe(gulp.dest('./static/css/'));
});

gulp.task('imagemin', function() {
    return gulp.src(['./assets/svg/**/*', './assets/img/**/*'])
        .pipe(imagemin({
            progressive: true,
            svgoPlugins: [
                {removeViewBox: false},
                {cleanupIDs: false},
            ],
        }))
        .pipe(gulp.dest('./static/img/'));
});

gulp.task('fonts', function() {
    return gulp.src('./assets/fonts/*')
        .pipe(copy('./static/fonts/', {prefix: 2}));
});

gulp.task('icons', function() {
    return gulp.src('./assets/icons/*')
        .pipe(copy('./static/', {prefix: 2}));
});

gulp.task('ga', function() {
    return gulp.src('./src/js/ga.js')
        .pipe(copy('./static/js/', {prefix: 2}));
});

gulp.task('js', function() {
    return gulp.src([
        './node_modules/jquery/dist/jquery.slim.min.js',
        './node_modules/magnific-popup/dist/jquery.magnific-popup.min.js',
        './assets/js/base.js',
        './assets/js/ga.js',
    ])
    .pipe(concat('all.min.js'))
    // .pipe(uglify({mangle: false}))
    .pipe(gulp.dest('./static/js/'));
});

gulp.task('default', ['sass', 'imagemin', 'fonts', 'js']);

gulp.task('watch', function() {
    gulp.watch('./gulpfile.js', ['default']);
    gulp.watch('./assets/scss/**/*.scss', ['sass']);
    gulp.watch(['./assets/svg/**/*', './assets/img/**/*'], ['imagemin']);
    gulp.watch('./assets/js/**/*', ['js']);
});
