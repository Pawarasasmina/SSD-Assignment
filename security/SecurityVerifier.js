const fs = require('fs');
const path = require('path');

class SecurityVerifier {
    constructor() {
        this.results = [];
        this.projectPath = process.cwd();
    }

    // Check Authentication & Authorization
    checkAuthentication() {
        console.log('🔐 Checking Authentication & Authorization...\n');
        
        // Check password hashing
        this.checkPasswordHashing();
        
        // Check authentication middleware
        this.checkAuthenticationMiddleware();
        
        // Check authorization consistency
        this.checkAuthorizationConsistency();
        
        // Check JWT best practices
        this.checkJWTBestPractices();
    }

    checkPasswordHashing() {
        try {
            const userModelPath = path.join(this.projectPath, 'backend/models/User.js');
            const userModel = fs.readFileSync(userModelPath, 'utf8');
            
            const hasBcrypt = userModel.includes('bcrypt');
            const hasComparePassword = userModel.includes('comparePassword');
            const hasPreSave = userModel.includes('pre(\'save\'') || userModel.includes('pre("save"');
            
            this.logResult('Password storage uses proper hashing', 
                hasBcrypt && hasComparePassword && hasPreSave,
                `bcrypt: ${hasBcrypt}, comparePassword: ${hasComparePassword}, pre-save hook: ${hasPreSave}`
            );
        } catch (error) {
            this.logResult('Password storage uses proper hashing', false, 'User model not found');
        }
    }

    checkAuthenticationMiddleware() {
        try {
            const routesPath = path.join(this.projectPath, 'backend/routes/userRoutes.js');
            const routes = fs.readFileSync(routesPath, 'utf8');
            
            const hasVerifyToken = routes.includes('verifyToken');
            const hasAuthHeader = routes.includes('Authorization');
            const hasJWTVerify = routes.includes('jwt.verify');
            
            this.logResult('Sensitive operations require authentication',
                hasVerifyToken && hasAuthHeader && hasJWTVerify,
                `verifyToken middleware: ${hasVerifyToken}, Authorization header: ${hasAuthHeader}`
            );
        } catch (error) {
            this.logResult('Sensitive operations require authentication', false, 'Routes file not found');
        }
    }

    checkAuthorizationConsistency() {
        try {
            const routesDir = path.join(this.projectPath, 'backend/routes');
            const routeFiles = fs.readdirSync(routesDir).filter(file => file.endsWith('.js'));
            
            let protectedRoutes = 0;
            let totalRoutes = 0;
            
            routeFiles.forEach(file => {
                const content = fs.readFileSync(path.join(routesDir, file), 'utf8');
                const routes = content.match(/router\.(get|post|put|delete)/g) || [];
                const protectedWithToken = content.match(/verifyToken/g) || [];
                
                totalRoutes += routes.length;
                protectedRoutes += protectedWithToken.length;
            });
            
            const consistencyRatio = totalRoutes > 0 ? (protectedRoutes / totalRoutes) : 0;
            
            this.logResult('Authorization checks are consistent across all routes',
                consistencyRatio >= 0.8, // 80% or more routes should be protected
                `${protectedRoutes}/${totalRoutes} routes protected (${Math.round(consistencyRatio * 100)}%)`
            );
        } catch (error) {
            this.logResult('Authorization checks are consistent across all routes', false, error.message);
        }
    }

    checkJWTBestPractices() {
        try {
            const routesPath = path.join(this.projectPath, 'backend/routes/userRoutes.js');
            const routes = fs.readFileSync(routesPath, 'utf8');
            
            const usesEnvSecret = routes.includes('process.env.JWT_SECRET');
            const hasExpiration = routes.includes('expiresIn');
            const noHardcodedSecret = !routes.match(/jwt\.sign.*["'][a-zA-Z0-9-_]{10,}["']/);
            
            this.logResult('JWT or session handling follows best practices',
                usesEnvSecret && hasExpiration && noHardcodedSecret,
                `Env secret: ${usesEnvSecret}, Expiration: ${hasExpiration}, No hardcoded: ${noHardcodedSecret}`
            );
        } catch (error) {
            this.logResult('JWT or session handling follows best practices', false, error.message);
        }
    }

    // Check Input Validation
    checkInputValidation() {
        console.log('\n📝 Checking Input Validation...\n');
        
        this.checkServerSideValidation();
        this.checkInjectionPrevention();
        this.checkFileUploadValidation();
    }

    checkServerSideValidation() {
        try {
            const routesDir = path.join(this.projectPath, 'backend/routes');
            const routeFiles = fs.readdirSync(routesDir).filter(file => file.endsWith('.js'));
            
            let hasValidation = false;
            let validationDetails = [];
            
            routeFiles.forEach(file => {
                const content = fs.readFileSync(path.join(routesDir, file), 'utf8');
                
                if (content.includes('express-validator') || 
                    content.includes('body(') || 
                    content.includes('validationResult')) {
                    hasValidation = true;
                    validationDetails.push(`${file}: express-validator`);
                }
                
                if (content.includes('joi') || content.includes('yup')) {
                    hasValidation = true;
                    validationDetails.push(`${file}: validation library`);
                }
            });
            
            this.logResult('All user inputs are validated',
                hasValidation,
                validationDetails.join(', ') || 'No validation found'
            );
        } catch (error) {
            this.logResult('All user inputs are validated', false, error.message);
        }
    }

    checkInjectionPrevention() {
        try {
            const routesDir = path.join(this.projectPath, 'backend/routes');
            const routeFiles = fs.readdirSync(routesDir).filter(file => file.endsWith('.js'));
            
            let hasInjectionPrevention = true;
            let issues = [];
            
            routeFiles.forEach(file => {
                const content = fs.readFileSync(path.join(routesDir, file), 'utf8');
                
                // Check for potential SQL/NoSQL injection patterns
                const dangerousPatterns = [
                    /\$where.*req\.(body|query|params)/g,
                    /find\(.*\+.*req\./g,
                    /exec\(.*req\./g
                ];
                
                dangerousPatterns.forEach(pattern => {
                    const matches = content.match(pattern);
                    if (matches) {
                        hasInjectionPrevention = false;
                        issues.push(`${file}: Potential injection in ${matches[0]}`);
                    }
                });
            });
            
            this.logResult('Input validation prevents injection attacks',
                hasInjectionPrevention,
                issues.length > 0 ? issues.join(', ') : 'No injection vulnerabilities found'
            );
        } catch (error) {
            this.logResult('Input validation prevents injection attacks', false, error.message);
        }
    }

    checkFileUploadValidation() {
        try {
            const serverPath = path.join(this.projectPath, 'backend/server.js');
            const serverContent = fs.readFileSync(serverPath, 'utf8');
            
            const hasMulter = serverContent.includes('multer');
            const hasFileFilter = serverContent.includes('fileFilter');
            const hasSizeLimits = serverContent.includes('limits');
            const hasFileTypeValidation = serverContent.includes('mimetype') || serverContent.includes('allowedFileTypes');
            
            this.logResult('File uploads have proper validation and restrictions',
                hasMulter && hasFileFilter && hasSizeLimits && hasFileTypeValidation,
                `multer: ${hasMulter}, fileFilter: ${hasFileFilter}, sizeLimits: ${hasSizeLimits}, typeValidation: ${hasFileTypeValidation}`
            );
        } catch (error) {
            this.logResult('File uploads have proper validation and restrictions', false, error.message);
        }
    }

    // Check Data Protection
    checkDataProtection() {
        console.log('\n🔒 Checking Data Protection...\n');
        
        this.checkSensitiveDataEncryption();
        this.checkSecretsInCode();
        this.checkErrorHandling();
        this.checkParameterizedQueries();
    }

    checkSensitiveDataEncryption() {
        try {
            const userModelPath = path.join(this.projectPath, 'backend/models/User.js');
            const userModel = fs.readFileSync(userModelPath, 'utf8');
            
            const hasBcryptHashing = userModel.includes('bcrypt');
            const hasPasswordHashing = userModel.includes('hashSync') || userModel.includes('hash(');
            
            this.logResult('Sensitive data is properly encrypted',
                hasBcryptHashing && hasPasswordHashing,
                `Password hashing implemented: ${hasBcryptHashing && hasPasswordHashing}`
            );
        } catch (error) {
            this.logResult('Sensitive data is properly encrypted', false, error.message);
        }
    }

    checkSecretsInCode() {
        try {
            const backendDir = path.join(this.projectPath, 'backend');
            const files = this.getAllJSFiles(backendDir);
            
            let secretsFound = [];
            const secretPatterns = [
                /password\s*[:=]\s*["'][^"']*["']/gi,
                /secret\s*[:=]\s*["'][^"']*["']/gi,
                /key\s*[:=]\s*["'][^"']*["']/gi,
                /token\s*[:=]\s*["'][^"']*["']/gi
            ];
            
            files.forEach(file => {
                const content = fs.readFileSync(file, 'utf8');
                secretPatterns.forEach(pattern => {
                    const matches = content.match(pattern);
                    if (matches) {
                        matches.forEach(match => {
                            if (!match.includes('process.env') && !match.includes('req.body')) {
                                secretsFound.push(`${path.basename(file)}: ${match.substring(0, 50)}...`);
                            }
                        });
                    }
                });
            });
            
            this.logResult('No secrets or credentials in the code',
                secretsFound.length === 0,
                secretsFound.length > 0 ? `Found: ${secretsFound.join(', ')}` : 'No hardcoded secrets found'
            );
        } catch (error) {
            this.logResult('No secrets or credentials in the code', false, error.message);
        }
    }

    checkErrorHandling() {
        try {
            const routesDir = path.join(this.projectPath, 'backend/routes');
            const routeFiles = fs.readdirSync(routesDir).filter(file => file.endsWith('.js'));
            
            let properErrorHandling = true;
            let issues = [];
            
            routeFiles.forEach(file => {
                const content = fs.readFileSync(path.join(routesDir, file), 'utf8');
                
                // Check for information leakage in error responses
                const errorLeakagePatterns = [
                    /res\.json\s*\(\s*error\s*\)/gi,
                    /res\.send\s*\(\s*error\s*\)/gi,
                    /console\.log\s*\(\s*error\s*\)/gi
                ];
                
                errorLeakagePatterns.forEach(pattern => {
                    const matches = content.match(pattern);
                    if (matches) {
                        properErrorHandling = false;
                        issues.push(`${file}: Potential information leakage`);
                    }
                });
            });
            
            this.logResult('Proper error handling without information leakage',
                properErrorHandling,
                issues.length > 0 ? issues.join(', ') : 'No information leakage found'
            );
        } catch (error) {
            this.logResult('Proper error handling without information leakage', false, error.message);
        }
    }

    checkParameterizedQueries() {
        try {
            const routesDir = path.join(this.projectPath, 'backend/routes');
            const routeFiles = fs.readdirSync(routesDir).filter(file => file.endsWith('.js'));
            
            let hasParameterizedQueries = true;
            let issues = [];
            
            routeFiles.forEach(file => {
                const content = fs.readFileSync(path.join(routesDir, file), 'utf8');
                
                // Check for proper MongoDB query patterns
                const mongoosePatterns = [
                    /findOne\s*\(\s*\{/gi,
                    /find\s*\(\s*\{/gi,
                    /updateOne\s*\(\s*\{/gi,
                    /deleteOne\s*\(\s*\{/gi
                ];
                
                let hasMongooseQueries = false;
                mongoosePatterns.forEach(pattern => {
                    if (content.match(pattern)) {
                        hasMongooseQueries = true;
                    }
                });
                
                if (hasMongooseQueries) {
                    // Check for string concatenation in queries (bad practice)
                    if (content.match(/find.*\+.*req\./gi)) {
                        hasParameterizedQueries = false;
                        issues.push(`${file}: String concatenation in queries`);
                    }
                }
            });
            
            this.logResult('Database queries are parameterized',
                hasParameterizedQueries,
                issues.length > 0 ? issues.join(', ') : 'Proper parameterized queries found'
            );
        } catch (error) {
            this.logResult('Database queries are parameterized', false, error.message);
        }
    }

    // Check Security Headers & Configuration
    checkSecurityConfiguration() {
        console.log('\n🛡️  Checking Security Headers & Configuration...\n');
        
        this.checkSecurityHeaders();
        this.checkCORSConfiguration();
        this.checkContentSecurityPolicy();
        this.checkResponseInformation();
    }

    checkSecurityHeaders() {
        try {
            const serverPath = path.join(this.projectPath, 'backend/server.js');
            const serverContent = fs.readFileSync(serverPath, 'utf8');
            
            const hasHelmet = serverContent.includes('helmet');
            const hasHelmetUse = serverContent.includes('app.use(helmet');
            const hasCustomHeaders = serverContent.includes('X-Frame-Options') || 
                                   serverContent.includes('X-Content-Type-Options');
            
            this.logResult('Security headers are implemented',
                hasHelmet && hasHelmetUse,
                `helmet: ${hasHelmet}, helmet.use: ${hasHelmetUse}, custom headers: ${hasCustomHeaders}`
            );
        } catch (error) {
            this.logResult('Security headers are implemented', false, error.message);
        }
    }

    checkCORSConfiguration() {
        try {
            const serverPath = path.join(this.projectPath, 'backend/server.js');
            const serverContent = fs.readFileSync(serverPath, 'utf8');
            
            const hasCORS = serverContent.includes('cors');
            const hasRestrictiveOrigin = serverContent.includes('origin:') && 
                                       !serverContent.includes('origin: true') &&
                                       !serverContent.includes('origin: "*"');
            const hasMethods = serverContent.includes('methods:');
            const hasCredentials = serverContent.includes('credentials:');
            
            this.logResult('CORS is properly configured',
                hasCORS && hasRestrictiveOrigin && hasMethods,
                `CORS: ${hasCORS}, restrictive origin: ${hasRestrictiveOrigin}, methods defined: ${hasMethods}`
            );
        } catch (error) {
            this.logResult('CORS is properly configured', false, error.message);
        }
    }

    checkContentSecurityPolicy() {
        try {
            const serverPath = path.join(this.projectPath, 'backend/server.js');
            const serverContent = fs.readFileSync(serverPath, 'utf8');
            
            const hasCSP = serverContent.includes('contentSecurityPolicy') || 
                          serverContent.includes('Content-Security-Policy');
            const hasDirectives = serverContent.includes('directives') || 
                                 serverContent.includes('defaultSrc');
            
            this.logResult('Content Security Policy is implemented',
                hasCSP && hasDirectives,
                `CSP headers: ${hasCSP}, directives defined: ${hasDirectives}`
            );
        } catch (error) {
            this.logResult('Content Security Policy is implemented', false, error.message);
        }
    }

    checkResponseInformation() {
        try {
            const routesDir = path.join(this.projectPath, 'backend/routes');
            const routeFiles = fs.readdirSync(routesDir).filter(file => file.endsWith('.js'));
            
            let hasInfoLeakage = false;
            let leakagePoints = [];
            
            routeFiles.forEach(file => {
                const content = fs.readFileSync(path.join(routesDir, file), 'utf8');
                
                // Check for unnecessary information exposure
                if (content.includes('error.stack') || 
                    content.includes('error.message') && content.includes('res.json(error')) {
                    hasInfoLeakage = true;
                    leakagePoints.push(`${file}: Error details exposed`);
                }
                
                // Check for password fields in responses
                if (content.match(/password.*res\.json/gi)) {
                    hasInfoLeakage = true;
                    leakagePoints.push(`${file}: Password in response`);
                }
            });
            
            this.logResult('No unnecessary information in HTTP responses',
                !hasInfoLeakage,
                leakagePoints.length > 0 ? leakagePoints.join(', ') : 'No information leakage found'
            );
        } catch (error) {
            this.logResult('No unnecessary information in HTTP responses', false, error.message);
        }
    }

    // Utility methods
    getAllJSFiles(dir) {
        let files = [];
        const items = fs.readdirSync(dir);
        
        items.forEach(item => {
            const fullPath = path.join(dir, item);
            const stat = fs.statSync(fullPath);
            
            if (stat.isDirectory() && !item.includes('node_modules')) {
                files.push(...this.getAllJSFiles(fullPath));
            } else if (item.endsWith('.js')) {
                files.push(fullPath);
            }
        });
        
        return files;
    }

    logResult(check, passed, details) {
        const status = passed ? '✅' : '❌';
        const result = { check, passed, details };
        
        console.log(`${status} ${check}`);
        if (details) {
            console.log(`   Details: ${details}`);
        }
        console.log('');
        
        this.results.push(result);
    }

    // Main verification method
    verify() {
        console.log('🔍 Starting Security Verification...\n');
        console.log('='.repeat(50));
        
        this.checkAuthentication();
        this.checkInputValidation();
        this.checkDataProtection();
        this.checkSecurityConfiguration();
        
        this.generateSummary();
        this.generateReport();
    }

    generateSummary() {
        console.log('='.repeat(50));
        console.log('📊 SECURITY VERIFICATION SUMMARY\n');
        
        const totalChecks = this.results.length;
        const passedChecks = this.results.filter(r => r.passed).length;
        const failedChecks = totalChecks - passedChecks;
        const passRate = Math.round((passedChecks / totalChecks) * 100);
        
        console.log(`Total Checks: ${totalChecks}`);
        console.log(`✅ Passed: ${passedChecks}`);
        console.log(`❌ Failed: ${failedChecks}`);
        console.log(`📈 Pass Rate: ${passRate}%\n`);
        
        if (failedChecks > 0) {
            console.log('🚨 FAILED CHECKS:');
            this.results.filter(r => !r.passed).forEach(result => {
                console.log(`   ❌ ${result.check}`);
                console.log(`      ${result.details}\n`);
            });
        }
        
        // Security score
        let securityScore = 'EXCELLENT';
        if (passRate < 50) securityScore = 'POOR';
        else if (passRate < 70) securityScore = 'FAIR';
        else if (passRate < 85) securityScore = 'GOOD';
        
        console.log(`🏆 Security Score: ${securityScore} (${passRate}%)`);
    }

    generateReport() {
        const report = {
            timestamp: new Date().toISOString(),
            summary: {
                totalChecks: this.results.length,
                passedChecks: this.results.filter(r => r.passed).length,
                failedChecks: this.results.filter(r => !r.passed).length,
                passRate: Math.round((this.results.filter(r => r.passed).length / this.results.length) * 100)
            },
            categories: {
                authentication: this.results.slice(0, 4),
                inputValidation: this.results.slice(4, 7),
                dataProtection: this.results.slice(7, 11),
                securityConfiguration: this.results.slice(11, 15)
            },
            results: this.results
        };
        
        const reportPath = path.join(this.projectPath, 'security-verification-report.json');
        fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
        
        console.log(`\n📋 Detailed report saved: ${reportPath}`);
    }
}

module.exports = SecurityVerifier;