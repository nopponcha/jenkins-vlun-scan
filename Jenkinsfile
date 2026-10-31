pipeline {
  agent any
  triggers { cron('H 7 * * 1') }   // weekly, Monday ~07:00
  options { timestamps(); buildDiscarder(logRotator(numToKeepStr: '20')) }
  parameters {
    string(name: 'TARGET_JENKINS_URL', defaultValue: '', description: 'Jenkins URL to scan (blank = this Jenkins)')
    string(name: 'PLUGINS_FILE', defaultValue: '', description: 'Optional plugins.txt / JSON exported by admin (path in workspace)')
    booleanParam(name: 'INSECURE', defaultValue: false, description: 'Skip TLS verification')
    booleanParam(name: 'NOTIFY_DEVOPS', defaultValue: false, description: 'Email DevOps when vulns found (needs Email Extension plugin)')
    string(name: 'DEVOPS_EMAIL', defaultValue: 'devops@example.com', description: 'DevOps recipients')
  }
  stages {
    stage('Scan') {
      steps {
        withCredentials([usernamePassword(credentialsId: 'jenkins-api-token', usernameVariable: 'JENKINS_USER', passwordVariable: 'JENKINS_TOKEN')]) {
          script {
            def url = params.TARGET_JENKINS_URL?.trim() ? params.TARGET_JENKINS_URL.trim() : env.JENKINS_URL
            def extra = ''
            if (params.INSECURE) { extra += ' --insecure' }
            if (params.PLUGINS_FILE?.trim()) { extra += " --plugins-file '${params.PLUGINS_FILE.trim()}'" }
            def rc = sh(returnStatus: true, script: "JENKINS_URL='${url}' python3 scan.py --out scan-output --fail-on-vuln${extra}")
            if (rc == 2) {
              env.VULNS_FOUND = 'true'
              unstable('Vulnerable Jenkins core/plugins found - see report')
            } else if (rc != 0) {
              error("scan.py failed (exit ${rc})")
            }
          }
        }
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'scan-output/**', allowEmptyArchive: true
      script {
        try {
          publishHTML(target: [reportDir: 'scan-output', reportFiles: 'report.html', reportName: 'Jenkins Vuln Report',
                               keepAll: true, alwaysLinkToLastBuild: true, allowMissing: true])
        } catch (NoSuchMethodError e) {
          echo 'HTML Publisher plugin not installed - report.html is in archived artifacts'
        }
        if (params.NOTIFY_DEVOPS && env.VULNS_FOUND == 'true') {
          try {
            emailext(to: params.DEVOPS_EMAIL, subject: "[Jenkins Security] Vulnerable core/plugins found (${env.JOB_NAME} #${env.BUILD_NUMBER})",
                     body: readFile('scan-output/summary.md') + "\n\nReport: ${env.BUILD_URL}artifact/scan-output/report.html",
                     attachmentsPattern: 'scan-output/report.html')
          } catch (NoSuchMethodError e) {
            echo 'Email Extension plugin not installed - skipping email'
          }
        }
      }
    }
  }
}
