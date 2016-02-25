#!node
"use strict";

var fs = require('fs');
var markdown = require('markdown').markdown;
var yamljs = require('yamljs');
var mustache = require('mustache');
var mkdirp = require('mkdirp');

var content = fs.readFileSync('./post.md', 'utf8');
var template = fs.readFileSync('./src/templates/template.html', 'utf8').toString();
var parts = content.split('---');
var meta = yamljs.parse(parts[1]);
meta.content = markdown.toHTML(parts[2]);
var rendered_page = mustache.render(template, meta);

mkdirp('./dist', function(err) {
    if (err) {
        console.error(err);
    }
});

fs.writeFile("./dist/index.html", rendered_page, function(err) {
    if (err) {
        return console.log(err);
    }
    console.log("Page rendered!");
});
