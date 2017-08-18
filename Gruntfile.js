module.exports = function(grunt) {
    grunt.loadNpmTasks('grunt-shell');
    grunt.initConfig({

        shell: {
            github: {
                command: 'git push -u origin master'
            },
            gitlab: {
                command: 'git push -u gitlab master'
            }
        }
    });


    grunt.registerTask('default', ['shell:github', 'shell:gitlab']);
};