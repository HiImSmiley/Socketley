#!/bin/bash
# =============================================================================
# campaign.sh - An advertisement to the customers a db runtime keeps
# =============================================================================
#
# Each customer gets a message of their own from autumn.html: their name and
# code where the template says {{name}} and {{code}}, a row for each of the
# picks their document lists, the shop's logo inside the message, and a link
# to unsubscribe of their own. campaign.lua leaves out who never ordered and
# marks each link to the shop with the campaign. Nothing is sent if the
# template asks for a value the first customer has not, and a later one who has
# not is skipped; --rate-limit keeps a new sender out of the spam folder. Whoever
# unsubscribed is skipped, and `socketley mail m unsubscribed` lists them.
# logo.png, beside this script, stands for the shop's logo.
# =============================================================================

set -e
cd "$(dirname "$0")"

# What the first customer's message says, nothing sent; then that one, to you.
socketley send m --template autumn.html --lua campaign.lua --inline logo.png --to db:shop/customers \
    --from news@example.com --subject 'Hello {{name|there}}, your code: {{code}}' --ad --test
socketley send m --template autumn.html --lua campaign.lua --inline logo.png --to db:shop/customers \
    --from news@example.com --subject 'Hello {{name|there}}, your code: {{code}}' --ad --test-to you@example.com

# All of them, five a second.
socketley send m --template autumn.html --lua campaign.lua --inline logo.png --to db:shop/customers \
    --from news@example.com --subject 'Hello {{name|there}}, your code: {{code}}' --ad --rate-limit 5
