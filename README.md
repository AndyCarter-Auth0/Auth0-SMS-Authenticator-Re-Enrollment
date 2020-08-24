# Auth0 SMS Authenticator Re-Enrollment

A customer may implement a custom database connection in Auth0 to connect to an existing user account datastore, to allow users in that datastore to authenticate to their application(s) in Auth0. User details for authentication are returned from the custom datastore using scripts.

Customers also have the option to enable migration of users from the custom datastore to Auth0 as part of the authentication process, however they may use their custom datastore without migrating users to Auth0.

An issue arises when a customer has a custom database connection, does not wish to import users to Auth0, however wants Auth0 to perform MFA authentication for users in their custom datastore.

This design is to allow customers to use Auth0 to perform MFA SMS authentication for users in a non migrating custom database connection, using existing details provided via the custom database connection and profile object. 

## Design documentation

[Custom Implementation Services](https://auth0.com/docs/services/packages#-custom-implementation-package-) to support functionality not supported out-of-the-box are provided by Auth0 Professional Services, and a wide variety of services are offered to help address a number of use case scenarios. These services can be leveraged to provide you with a complete solution for Verified Email Address Change - in either a stand-alone fashion or in conjunction with other customization. However we also provide you with full design documentation (see below) if you prefer to implement yourself. 

Detailed design documentation (follow link above to access) provides you with a comprehensive set of information that is implementation agnostic. Using this, you and your team can implement Verified Email Address Change workflow whatever the technology stack you currently, or indeed plan, to utilize. The information is provided free of charge and without warranty (either explicit or implied).    

## Reference implementation

This repository also contains reference implementation developed using [.NET Core](https://dotnet.microsoft.com/), and is provided to accelerate development of that part of the design which deals with actual re-enrollment of SMS factors. This implementation is provided free of charge and without warranty either explicit or implied. 


### Auth0 Configuration

The [Tenant](tenant) folder contains reference Auth0 Tenant configuration and asset definitions that can be used as a basis to build out functionality in order to support Verified Email Address Change. For further details please refer to the [readme](Tenant) contained in the folder.

## About Auth0

Auth0 is the flagship Platform-as-a-Service (PaaS) Identity and Access Management service from the company of the same name. Auth0 helps you to easily:

- authenticate using multiple identity providers, including social (e.g. Google, Facebook, Microsoft, LinkedIn, GitHub, Twitter, etc), or enterprise (e.g. Windows Azure AD, Google Apps, Active Directory, ADFS, SAML, etc),
- authenticate users via username/password, or passwordless mechanisms,
- implement multi-factor authentication,
- link multiple user identities to a single user account, 
- generate signed JSON Web Tokens to authorize API calls and flow user identity securely,
- access demographics and analytics, detailing how, when, and where users are logging in
- enrich user profiles from other data sources using customizable JavaScript Rules,
- and much, much more.
 
Go to [Auth0](https://auth0.com) and click Sign Up to create a free account.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them via the issues section of this repository. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## License

This project is licensed under an MIT LICENSE. Please see the [LICENSE](LICENSE) file for more info.
