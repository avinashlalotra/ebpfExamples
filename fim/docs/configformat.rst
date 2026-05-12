================================================================================
POLICY CONFIGURATION FORMAT SPECIFICATION
================================================================================

SYNTAX
------

config      ::= section+

section     ::= api_section | rules_section

api_section ::= "API_URL:" whitespace? url 
              | "API_PORT:" whitespace? port
              | "API_HEADER:" whitespace? header

rules_section ::= rule+

rule        ::= command ":" whitespace? argument

command     ::= "D" | "E" | "IF" | "EE" | "ES" | "EP" | "P"

argument    ::= path | list | extension | suffix

path        ::= absolute_path
list        ::= item ("," item)*
extension   ::= "." extension_name
suffix      ::= suffix_name

absolute_path must start with "/"
whitespace after colon is optional


API CONFIGURATION
-----------------

API_URL: <url>
    Endpoint used for sending policy results, reports, or telemetry.
API_PORT: <port>
    Port number for 
API_HEADER: <key>=<value>
    HTTP header included in API requests.
    Multiple headers may be specified using multiple API_HEADER entries.


RULE COMMANDS
-------------

D: <path>
    Include directory (recursive) or include a single file.

E: <path>
    Exclude directory (recursive). Entire subtree skipped during traversal.

IF: <path>
    Force include file or directory. Overrides all exclusions.

EE: <ext>
    Exclude file extensions (must not include dot, e.g. "log").

ES: <suffix>
    Exclude filename suffixes

EP: <prefix>
    Exclude filename prefixes
P: <pattern>
    Exclude patterns

API HEADER FORMAT
-----------------

Header syntax:

API_HEADER: Header-Name=Header-Value

Examples:

API_HEADER: Authorization=Bearer abc123
API_HEADER: Content-Type=application/json
API_HEADER: X-Agent-ID=node-01


EXAMPLE
-------

API_URL:security.example.com/v1/policy/report
API_PORT: 8888
API_HEADER: Authorization=Bearer
API_HEADER: Content-Type=application/json
API_HEADER: X-Agent-ID=host-01

D: /opt/app
E: /opt/app/cache
EE: log
ES: _old
IF: /opt/app/cache/critical.log


NOTES
-----

- Unknown commands must be rejected during parsing.
- Paths must be absolute.
- Multiple API headers are allowed.
- Duplicate rules are not allowed

================================================================================
END OF SPECIFICATION
================================================================================