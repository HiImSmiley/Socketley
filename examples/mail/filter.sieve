# filter.sieve - A user's Sieve filter, put with
#   socketley mail m sieve alice put main filter.sieve
#   socketley mail m sieve alice activate main
# or from a mail client over ManageSieve on --sieve 4190.
require ["fileinto", "mailbox", "imap4flags", "vacation", "envelope", "subaddress", "variables"];

# Mailing lists into a folder of their own, by the list's name.
if header :matches "List-Id" "*<*.*>*" {
    fileinto :create "Lists/${2}";
    stop;
}

# alice+invoices@example.com, flagged, into Invoices.
if envelope :detail "to" "invoices" {
    fileinto :flags "\\Flagged" "Invoices";
    stop;
}

# Away for a week: each sender is answered once.
vacation :days 7 :subject "Away until Monday"
    "I am away until Monday and will answer then.";
