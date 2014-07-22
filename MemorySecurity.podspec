Pod::Spec.new do |s|
    s.name          = 'MemorySecurity'
    s.version       = '1.0'
    s.license       = 'Apache License 2.0'

    s.summary       = 'Tools for securely clearing and validating iOS application memory'
    s.description   = %[
        The "iMAS Secure Memory" framework provides a set of tools for securing, clearing, and validating memory regions and individual variables. It allows an object to have its data sections overwritten in memory either with an encrypted version or null bytes.
    ]
    s.homepage      = 'https://github.com/project-imas/memory-security'
    s.authors       = {
        'MITRE' => 'imas-proj-list@lists.mitre.org'
    }
    
    s.source        = {
        :git => 'https://github.com/project-imas/memory-security.git',
        :tag => s.version.to_s
    }
    s.source_files  = 'IMSHandler/*'

    s.platform      = :ios
    s.ios.deployment_target = '6.1'
    s.requires_arc  = true

#   SecureFoundation podspec is not in the official Cocoapods spec repo
#   remember to include it in your Podfile BEFORE you include MemorySecurity
    s.dependency 'SecureFoundation', '~> 1.0'
end