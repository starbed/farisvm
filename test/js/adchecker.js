var filterFiles = {
    "../../tools/easylist.txt": "easylist",
    "../../tools/easylist_france.txt": "easylist france",
    "../../tools/easylist_germany.txt": "easylist germany",
    "../../tools/easylist_italy.txt": "easylist italy",
    "../../tools/easyprivacy.txt": "easyprivacy",
    "../../tools/fanboy_annoyance.txt": "fanboy annoiance",
    "../../tools/japanese.txt": "japanese",
    "../../tools/japanese_tofu.txt": "japanese (tofu)",
    "../../tools/malwaredomains_full.txt": "malwaredomains"};

var fc = require('./filterClasses.js');

function filterRule (rule) {
    this.files  = {};
    this.filter = fc.Filter.fromText(rule);
}

filterRule.prototype.addFile = function (file) {
    this.files[file] = filterFiles[file];
}

filterRule.prototype.matches = function (url) {
    var sp = url.split('/');

    if (sp.length > 3) {
        return this.filter.matches(url, sp[2]);
    } else {
        return this.filter.matches(url);
    }
}

function loadFilter() {
    var fs = require('fs');
    var filters = {};
    var n = 0;

    for (i in filterFiles) {
        var text  = fs.readFileSync(i, 'utf8');
        var rules = text.split('\n').slice(1);

        for (var j = 0; j < rules.length; j++) {
            if (rules[j] == '' || rules[j][0] == '!' ||
                rules[j].slice(0, 2) == "##") {
                continue;
            }

            if (rules[j] in filters) {
                filters[rules[j]].addFile(i);
            } else {
                var rule = new filterRule(rules[j]);

                if (rule.filter == null)
                    continue;

                rule.addFile(i);

                filters[rules[j]] = rule;
                n++;
            }
        }
    }

    // console.log(n);

    return filters;
}

var filters = loadFilter();
var reader = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
});

reader.setPrompt('');
reader.prompt();

reader.on('line', function (line) {
    var result = {result: false, rules: {}};
    var t0 = process.hrtime();
    for (var key in filters) {
        if (filters[key].matches(line)) {
            result['result'] = true;
            result['rules'][filters[key].filter.text] = filters[key].files;
        }
    }
    var t1 = process.hrtime(t0);

    console.log(JSON.stringify(result));
    console.log('%d [us]', Math.round(((t1[0] * 1e9 + t1[1]) / 1000)));
});

process.stdin.on('end', function () {
    //do something
});
