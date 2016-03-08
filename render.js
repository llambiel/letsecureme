#!node
"use strict";

var fs = require('fs');
var markdown = require('markdown').markdown;
var yamljs = require('yamljs');
var mustache = require('mustache');
var mkdirp = require('mkdirp');

var content = fs.readFileSync('./post.md', 'utf8');
var parts = content.split('---');
var meta = yamljs.parse(parts[1]);
meta.content = markdown.toHTML(parts[2]);
meta.intro = markdown.toHTML(meta.intro);

var templates = [
    {
        src: './src/templates/template.html',
        dest: './dist',
    },
    {
        src: './src/templates/demo-page.html',
        dest: './demo',
    },
];

templates.forEach(function(template) {
    mkdirp(template.dest, function(err) {
        if (err) {
            console.error(err);
        }
    });
    var template_file = fs.readFileSync(template.src, 'utf8').toString();
    var rendered_page = mustache.render(template_file, meta);
    var dest = template.dest + '/index.html';
    fs.writeFile(dest, rendered_page, function(err) {
        if (err) {
            return console.log(err);
        }
        console.log("Page rendered!");
    });
});
