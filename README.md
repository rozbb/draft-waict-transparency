# WAICT Transparency for the Browser

[Web Application Integrity, Consistency, and Transparency (WAICT)](https://docs.google.com/document/d/16-cvBkWYrKlZHXkWRFvKGEifdcMthUfv-LxIbg6bx2o/edit?tab=t.0#heading=h.hqduv7qhbp3k) is a specification for web browsers and website owners, describing how to enforce content integrity for an entire website. At a high level, it specifies how to parse and interpret a _manifest_, which contains the hash of every file that the website will serve.

An introductory blog post can be found [here](https://blog.cloudflare.com/improving-the-trustworthiness-of-javascript-on-the-web/).

These specifications propose a set of protocols to provide _consistency_ and _transparency_ to the distribution of manifest files. That is, they proposes system by which end users can be assured that the manifest they receive is the same manifest all other end users receive, and by which third party auditors can review all the code committed to in a manifest, even long after the manifest was served to an end user.

# License

All work in this repo is marked by Michael Rosenberg with [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/).
