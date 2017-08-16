module.exports = function(grunt) {
    grunt.loadNpmTasks('grunt-shell');
    grunt.initConfig({

        shell: {
            build: {
                command: 'powershell .\\build.ps1'
            },
            github: {
                command: 'git push -u origin master'
            },
            gitlab: {
                command: 'git push -u gitlab master'
            }
        }
    });


    grunt.registerTask('default', ['shell:build', 'shell:github', 'shell:gitlab']);
};