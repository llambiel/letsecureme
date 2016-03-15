'use strict';

var gulp = require('gulp');
var imagemin = require('gulp-imagemin');


gulp.task('imagemin', function() {
    return gulp.src(['./src/svg/*', './src/img/**/*'])
        .pipe(imagemin({
            progressive: true,
            svgoPlugins: [
                {removeViewBox: false},
                {cleanupIDs: false},
            ],
        }))
        .pipe(gulp.dest('./static/img/'));
});

gulp.task('watch', function() {
    gulp.watch(['./src/svg/*', './src/img/*'], ['imagemin']);
});

gulp.task('default', ['imagemin']);
