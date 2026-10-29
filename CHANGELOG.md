# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **A runtime others name is not renamed from under them.** A rename by
  `import` or the dashboard left a proxy's backend, a server's cache, and the
  mail runtimes, storages, edges, dbs and brokers signing people in at an idp
  naming one that was no longer there; it is now refused with each of them
  said, until they name another.
- **A tunnel edge tells a link why it closes before closing it.** A person
  signed out, or a share whose time was up, read only that the edge closed the
  connection, as the edge closed it before its last word was written.
- **A runtime in the dashboard's sidebar has its actions on a right click.**
  Start or stop, restart, reload Lua, edit and remove, and a link to where it
  is served, as its page offers them, beside each name with its type's icon.
- **A tunnel can be made and edited in the dashboard.** The schema the page
  builds its forms from named a tunnel's settings as a DNS runtime's and
  offered it no port, start, bind, names or state log, so an edit showed no
  field; an edge's form now shows an edge's settings and an agent's an
  agent's.
- **An edit's ACME names and address are taken.** `import`, which the
  dashboard saves an edit through, passed over `acme_domains` and
  `acme_email` and answered as if it had saved them; they are now checked and
  applied as `--acme` and `--acme-email` are, the certificate's files with
  them.
- **A tunnel agent refuses an edge's settings.** `-p`, `--domain`,
  `--forward`, `--idp` and `--idp-audience` on an agent were kept and never
  read, while an edge already refused an agent's; they are now refused by
  name.
- **The MQTT WebSocket ping flood test sends a stream the broker can read.** On
  a short send it began its 1000-frame chunk again instead of going on, cutting
  a frame in two, so the broker rightly refused it and the test failed on the
  reset; the broker itself loses no byte under the flood.
- **A script's `socketley.start` answers once the runtime serves.** It forked
  the workers before answering but did not wait for them, so a script that
  started a server and reached it at once could still find the port closed on a
  busy machine; it now waits as the CLI's `start` does, and a worker's refusal
  is the answer the script gets.
- **Guesses sent at once over an idp's shards share one budget.** With
  `--shards N`, each shard counted only the sign-ins it was checking itself,
  so a burst spread over them was let through N times over before the first
  failure was counted; an attempt being checked is now counted at every shard
  while it is.
- **Another site cannot sign a browser out of the idp unasked.** `/logout`
  ended the browser's session for any page that sent it there, a link or an
  image's worth; a request another site sent, by `Sec-Fetch-Site` or its
  Origin or Referer, is now asked "Sign out?" first, unless the application
  names the account by an `id_token_hint` it was given.
- **Signing out at the idp ends the session, not only its cookie.** `/logout`
  cleared the browser's cookie and nothing else, so a copy of it, kept by
  whoever had taken it, went on signing in at the provider and every proxy,
  storage and dashboard for up to a month; the session is now ended at the
  provider and, by the standing it publishes, everywhere it is taken, the
  account's other sessions kept.
- **A person's tunnel link ends when the idp takes the sign-in back.** The
  edge checked the access token once, when the link was opened, and kept
  its admin bit as it was then, so an account signed out everywhere,
  disabled or taken out of admins kept the link and an admin's reach to
  every agent's ssh for as long as it answered pings; the link is now asked
  about again at every stream and once a second, closed when the sign-in no
  longer holds, and an admin taken out reaches no agent at the next stream.
- **A tunnel agent is never handed a visitor's idp session.** The edge
  checked a protected service's visitors and then carried the request on as
  it came, the `skl_idp` cookie that signs in at every runtime trusting the
  idp and the token or key the edge took among it, so the machine at home,
  perhaps someone else's, could sign in as any admin who visited it; an open
  service under the cookie domain was sent the cookie unasked. Every HTTP
  request now reaches the agent without the idp's cookies, and without its
  `Authorization` where the service asks for one.
- **One address holds at most twenty waiting device sign-ins at the idp.**
  `/device_authorization` asks a public client for no secret, so anyone
  could fill the ten thousand grants a shard keeps and refuse every
  `socketley login` for as long as they went on; an address, or an IPv6
  /48, past twenty grants waiting is now told to try again later.
- **The idp counts a mail runtime's wrong passwords at the account.** Its
  check for mail kept no count, so IMAP, POP3 and SMTP from the mail runtime's
  own machine, which mail does not guard, guessed an account's password as
  fast as the hashing threads ran; ten failures from such a client now hold
  the next up as ten sign-ins do, under a count of mail's own so a phone with
  an old password never holds up the web sign-in, and mail says the account
  cannot be checked now.
- **A renamed idp account signs in again.** `idp-user set user
  username=new` left its sessions and tokens working with the old name in
  them, which a storage and the mail take as the account they open, so the
  next account given that name was reached with them; a new username now ends
  them as `idp-user logout` does.
- **One address's failures no longer lock everyone behind it out of the idp.**
  Five failed sign-ins, or five requests to `/token` naming a client that
  does not exist, which any web page can send from a visitor's browser,
  refused every sign-in and token exchange from that address for a quarter
  of an hour, right passwords and valid clients included. A browser an
  account signed in on before is now held to the account's own limit alone,
  a client that is unknown or public is refused without counting, and only a
  confidential client's wrong secrets count, against that address's secrets.
- **The idp bars an IPv6 /48 past eighty failed sign-ins.** Each /64 had
  its own five, so a site's /48 gave one attacker 65536 budgets of five
  guesses each a quarter of an hour; the /48 now shares one budget of
  sixteen /64s' worth, beside each /64's own.
- **A request body the client stops sending is its own timeout.** A client
  that sent half its body and stopped reached `--backend-timeout` with the
  backend holding all it was given, and the proxy charged the backend and
  answered 504, so five stalled uploads opened the circuit breaker on a
  healthy backend for everyone; such a request is now answered 408 and is
  neither charged nor retried.
- **A connection the proxy's `--auth` let in ends when its sign-in does.**
  `--auth` was asked once per request head, so a websocket or other upgrade,
  and an answer still streaming, went on after its token left the file or its
  idp sign-in was ended or its account disabled; such a connection is now
  asked again every second and closed once it would be refused.
- **An HTTP/2 or HTTP/3 stream's answer pauses its backend like a socket's.**
  A stream's answer was framed into the stream's own buffer at once, and the
  backend's read paused only on the stream's write queue, which that leaves
  empty, so a client that granted no window held whole answers in the
  entrance; the pause now counts what the stream still holds, and the wire
  taking it resumes the backend.
- **An HTTP/2 client that does not read cannot grow the entrance's queue.**
  A frame that draws an RST_STREAM, such as a PRIORITY of the wrong length,
  drew one per frame with no count, and a session's queue had no bound beside
  the one on DATA; past 400 such resets in ten seconds the connection now ends
  with GOAWAY ENHANCE_YOUR_CALM, and a session that leaves 4 MiB unread is
  closed.
- **ffmpeg opens no URL an object names.** A thumbnail of an object that was
  an HLS playlist, read over the listener as an encrypted, compressed or
  tiered one is, made ffmpeg GET every segment URL it listed, on any host:
  a blind request from the storage host to its own network. ffmpeg and
  ffprobe now take only the protocol of their input and the demuxers of one
  file.
- **A storage interface cookie signed out stays signed out.** Its times
  were read with `strtoll`, so `+`, a leading zero or a blank spelled the
  same cookie another way: the seal still held, and the sign-out's mark,
  kept under the hash of the text signed out, was not found. Only the
  spelling a sign-in writes is taken now.
- **A Sieve reject bounces only to a sender something vouches for.** A
  stranger could name anyone as MAIL FROM, trip a user's `reject` rule, and
  have this host mail the refusal, with the whole message under RET=FULL, to
  that address. The refusal now goes to a signed-in user, this machine, or a
  sender whose domain's SPF passed for the peer; any other such message is
  discarded.
- **A Sieve vacation answers no spam.** A message Rspamd, Bayes or DMARC
  quarantine filed in Junk was answered by a user's `vacation`, which told
  its sender the address is read; the JMAP VacationResponse already skipped
  it, and both now ask one test.
- **A tunnel's TCP visitor is no program of the agent's machine.** An agent
  dialled a service at 127.0.0.1 from 127.0.0.1, so a mail runtime offered as
  `--tcp smtp:25=127.0.0.1:25` took every sender on the internet for this
  machine's own programs: relayed to anywhere, signed in without TLS or
  lockout, and skipped SPF, DMARC, DNSBL and greylisting. A TCP visitor now
  comes from 127.0.0.2; an HTTP service, behind the entrance, still from
  127.0.0.1.
- **A peer that trickles its request holds up no other on the metrics
  port.** The endpoint read one connection at a time for up to fifteen
  seconds each, so a few connections sending a byte a second stalled every
  scrape, the dashboard and the history; requests are now read side by
  side, each given five seconds to arrive whole, and an answer three to
  leave.
- **Signing out of the dashboard ends the session at the daemon.** A
  copy of the cookie stayed good for its twelve hours after sign-out, and
  after its key was removed from the credentials file or given another
  secret; the daemon now keeps its sessions and ends them at any of the
  three.
- **The dashboard takes X-Forwarded-For only from 127.0.0.1 or ::1, and
  only an address.** Any loopback peer could name a new client with each
  failed sign-in and never be barred, and a bare LF in the field wrote a
  log line of its choosing; a field with a control byte is now refused and
  a hop that is no address counts against the peer.
- **A dashboard without credentials shows the figures and not the log or a
  zone.** Its loopback port answered `/api/logs` and `/api/zone` to every
  local user, handing out the daemon's log and zone files the state
  directory keeps from them; both now need a session, 403 while none can
  be made.
- **The dashboard logs a mail relay without its password.** A `create` or
  `edit` with `--relay smtps://user:password@host` was written to the
  daemon's log and its ring as typed, which every later session reads; the
  password is now `***` there, as `show` gives it.
- **A tunnel agent reaches an edge over plain http only on this machine.**
  The man page said `http://` was for an edge on the same machine, but any
  host was taken, so the one-time invitation, the agent's key and the CLI's
  sign-in went over the network in clear; `--to`, `tunnel join` and
  `tunnel connect`/`ssh` now refuse an `http://` address that is not
  localhost, 127/8 or `[::1]`.
- **Without a home directory the state lies in a /tmp folder of the user's
  own.** The fallback was one shared `/tmp/socketley-runtimes`, which another
  user could make first and so read the runtimes' secrets and the ACME keys
  in it, or plant a link where a key was about to be written; it is now
  `/tmp/socketley-runtimes-<uid>`, made 0700 and refused by the daemon,
  export and restore when it is anybody else's or open to them. A key's
  scratch file is made new and never through a link.
- **git-sync trusts only the storage runtime's own certificate.** With
  `--ca` naming a fullchain file, as an `--acme` storage hands it, every
  certificate in it was an anchor and no name was checked, so any leaf the
  same public intermediate signed took the credentials; now the peer must
  show the file's first certificate.
- **One MQTT client filling the session table locks nobody else out.**
  Sessions kept by clean session 0 outlive their connection for a day, so one
  account, or anyone under `--anonymous`, could connect 100000 times with fresh
  client ids and leave every new client refused with 0x97 until they expired. A
  new client past `--max-sessions` now ends the session away longest of
  whoever holds the most (a user, or an address for clients without one) when
  that is two or more, counted as `sessions_evicted`; only otherwise is it
  refused.
- **MQTT topic rules that lead to each other end.** Two `mqtt://` rules
  pointing at each other's broker with `%t`, or one pointing back at its own,
  passed one publish round for ever, delivered again on every pass. A message
  now carries how many such rules it has passed, and after eight no further
  `mqtt://` rule takes it; each refusal is counted in the rule's `dropped`.
- **An MQTT message waiting in a session is checked against the rules as it
  leaves.** A QoS 1 or 2 message was judged by `--acl` when it was routed and
  sent from the session's queue or resent from its window whenever the client
  came back, so a rule taken away while a client was offline still let it have
  what had been queued for it. The read is now asked again as each queued
  message leaves and as unanswered ones are resent; one refused is counted as
  `dropped_denied`.
- **An MQTT session is its user's.** A CONNECT with another client's id took
  that client's session over whatever account it came with: the device was
  disconnected, its queue and subscriptions were handed to the newcomer, and a
  `%c` rule gave the newcomer the device's topics; with a clean start the
  session was ended. A session made under one user is now refused to every
  other (`0x87`, `5` for 3.1.1), on any shard, and its own connection stays;
  counted as `takeovers_refused` and `session_claims_refused`.
- **A sync's credentials file must be its owner's alone.** A `--credentials`
  file other users could read, as one written under umask 022 is, was taken
  without a word, and its secret signs as the storage's user for anyone on the
  machine. Such a file is now refused at create, at start and at every read,
  with `chmod 600 it`, as the storage's SSE key file already is.
- **A sync acts on no listing that says it is incomplete.** A storage that
  answered `IsTruncated` true with no continuation token, as one speaking
  ListObjects V1 does after 1000 keys, was taken as the whole bucket, and every
  carried file past that page was removed here. Such a listing, or one handing
  back the token just sent, is now a failed listing: it is said in
  `last_error`, nothing is brought or removed, and the listing is retried.
- **A script holds at most 128 MiB and returns at most 64 MiB.** EVAL's
  `string.rep` and `..` build strings in C, where the deadline never fires, and
  the reply was a second copy, so `EVAL "return string.rep('a',2e9)" 0` took
  4 GB of the worker's memory. The script's state now refuses growth past
  128 MiB while it runs (`-OOM`), `string.rep` refuses a result past it
  before building it, and a reply past 64 MiB is an error.
- **A script's pattern match is stopped by the deadline.** `string.find`,
  `match`, `gmatch` and `gsub` backtracked inside one C call where the count
  hook never fires, so `EVAL "return string.find(string.rep('a',1e5),'a*a*b')" 0`
  held the shard for hours. EVAL's string library now matches with Lua 5.1's
  rules in a matcher that looks at the deadline as it works, and refuses a
  pattern nested more than 200 deep, as Lua 5.2 does.
- **What a provider or an edge sends reaches the terminal as text.** `login`
  and `tunnel` printed a provider's sign-in page, code and refusals, and an
  edge's refusals and named idp, as they came, so escape sequences in them
  could show the person a link to another page than the one named, or
  overwrite what was printed before; each control character is now a `?`.
- **`mail export` writes only into a directory of its own.** It made the
  directory and reopened each mbox file by its path, following links, so
  another local user who could create `/var/tmp/socketley-mail` (the default
  parent) could swap the directory or a file for a link of theirs and read
  the mailbox; the directory is now refused when it is a link or its parent
  is a folder another user may change, and every file is opened below it.
- **An MQTT client identity the broker assigns is drawn from the kernel.** It
  came from a Mersenne Twister seeded with 32 bits, whose few outputs in one
  `auto-` identity let a client work out the identities given to others next
  and take over a session one of them kept.
- **A Raft port holds a connection to its hello.** An inbound link that had
  not said who it is was kept for as long as it stayed open under
  `--raft-insecure` (or after any handshake with an enrolled certificate),
  could announce a 16 MiB first frame, and 256 of them, or of TLS handshakes
  begun over and over, made the node close every member's connection; such a
  link now goes after 3 s or at a first frame longer than a hello, and a full
  table closes its oldest one to take the next connection.
- **A db stream that does not read holds 256 KiB of changes, not the history.**
  A stream of a public collection opened from an early change copied every
  change the database keeps, about 32 MiB, into memory at once, for anybody
  and for every such stream, and one that stopped reading held each change
  made since up to 16 MiB; a stream now takes changes from the history only as
  it drains, and one the history has gone past is told `reset`.
- **A db query reads at most 8 MiB of documents for what no index answers,
  unless a key asks.** A condition or a sort on a field the schema does not
  index read every document of the collection on the loop, and anybody may
  query a public or catalog one; past the bound it is now refused with 400
  `needs_index`. A query without a sort now also stops once it has its page.
- **A db collection's ids are hashed under a key of the process.** The map of
  a collection's documents probed from std::hash's low bits, whose seed is
  fixed, so ids chosen offline crowded one run of the table and made every
  write, read and delete in that collection walk it; it now uses SipHash-2-4
  under a key drawn at start.
- **An MQTT publisher does not name who owns the document a db rule writes.**
  A `db://` rule puts a JSON object as the document with the daemon's own
  rights, which take `_owner` from the body, so a publisher could hand a
  document to any account or take one from its owner; the payload's `_owner`
  is now dropped, and JSON that is no object is carried as other payloads are.
- **A condition on another account's document says nothing of it.** In an
  owner collection a write with `If-Match` or `If-None-Match: *` to a document
  another account holds was answered 412 with its version, or that it exists,
  before the account was judged; it is now answered 404 as a plain write is.
- **A presigned request is its signer's however it spells the signing
  parameters.** A URL whose `X-Amz-Algorithm` (or V2 `AWSAccessKeyId`) name was
  percent-encoded was verified with the signer's key but then judged as
  anonymous, so Deny statements naming the signer did not apply to it and a
  bucket policy could be put by a user who owns nothing.
- **An app password removed while another is made stays removed.** Making
  one on the account page wrote back the list as it was read before its
  password was checked and hashed, so one removed meanwhile, there or with
  `idp-user`, signed mail apps in again; the list is now read again after the
  hash, and both making and removing write only while it is still what they
  read.
- **A session alone makes no app password and turns no second step on or off.**
  The account page made an app password, a way into the mail that outlives
  the session, and began a second step on the session cookie alone; both now
  ask for the password again, or a code where a second step is on, counted as
  a sign-in's are, and turning one off counts its wrong codes. Signing out
  everywhere, a new password, `idp-user passwd` and `idp-user logout` now end
  the account's app passwords too, where they went on signing mail apps in.
- **A second step that is on is replaced only by turning it off.** The
  account page's `do=start` and `do=confirm` replaced the authenticator key of
  an account that had one with no code of it, so a stolen session could swap
  in a key of its own and lock the owner out; both are now refused while one
  is on, and a key begun while it was off no longer replaces one turned on
  meanwhile.
- **A proxy with `--auth idp:` keeps the provider's cookies from its backend.**
  The backend was handed the `skl_idp` session cookie with the rest of the
  Cookie field, and could replay it at every runtime that trusts the provider,
  the provider itself included; it now gets every other cookie, and learns who
  is signed in from `X-Forwarded-User` alone.
- **Mail counts an IPv6 client by its /64.** The ten failed sign-ins that
  lock an address out, and the connections and messages an address may have,
  were counted per address, so one /64 tried a password at every account from
  a fresh address each time and was never locked out; they are counted per
  /64 now, as the idp counts them.
- **`idp-user import` makes no storage admin an idp admin.** A storage user
  with the admin bit became a member of `admins`, which is root on every host
  that trusts the idp's SSH CA, so a storage admin could hand out root by
  making an admin user before an import; it now comes over as no admin, and
  the import names it with the `set` that makes it one.
- **A request field name that is not a token is a 400.** A name with a
  control byte, DEL or NUL in it, such as `Transfer-Encoding<VT>`, was no
  framing field to the proxy, server, storage or tunnel and went on to the
  backend verbatim, where a parser that trims it framed the body by it and
  read a second request the proxy never routed or authenticated.
- **A proxy `--auth` that is none of `bearer:`, `basic:` or `idp:` refuses
  every request.** Only the flag judged it: from saved state, a restored
  archive or `import` (and so `edit`), a misspelt spec such as
  `Bearer:/etc/tokens` meant no authentication at all and said nothing. The
  proxy now logs why and refuses everybody, and `import` refuses the
  document with the flag's sentence.
- **An h2c upgrade is not relayed by the proxy.** A request offering
  `Upgrade: h2c` reached the backend with its offer and `HTTP2-Settings`, and
  after a 101 the client spoke HTTP/2 to the backend past `--auth`, filters,
  routes and the `X-Forwarded-User` strip; the offer is now stripped and the
  request answered as the plain one it carries, while WebSocket and other
  upgrades are relayed as before.
- **A backend answer whose field name is not a token is never pooled.** A
  `Content-Length<VT>` or a NUL in a response field name framed the answer one
  way for the proxy and another for a lenient client; such a backend socket
  is now relayed to its close and not reused.
- **A client cannot forge fields of a bucket's access log.** The request line
  was written into its quoted field as sent, so a `"` in the path closed it,
  and the version and host fields took a header's spaces as they came, each
  adding fields a parser reads by position, from a request with no credentials
  at all. Every field a client writes is now percent-encoded where a byte would
  end or split it, and the Version Id is the request's `versionId`, as in S3.
- **An object key is UTF-8.** A PUT, POST, copy or multipart upload took any
  bytes as its key, `%FF` included, and ListObjects wrote them out raw in a
  document it declares UTF-8, so one writer made the bucket's listing
  unparseable for every client not asking for `encoding-type=url`; such a key
  is now 400 InvalidArgument. Keys already stored can still be deleted.
- **A grant by e-mail names nobody when two users give the address.** An
  invitee chose its own e-mail, unchecked, and a grant by that address went to
  the first user holding it by id, so one invited as `aaron` with the address
  of `ceo` took every grant meant for `ceo`; such a grant is now
  UnresolvableGrantByEmailAddress, and addresses are compared without case.
- **A user's own Deny of the bucket policy operations holds on its own bucket.**
  A bucket's owner and an admin were let set, read and delete its policy past
  every policy, so an explicit Deny of PutBucketPolicy or DeleteBucketPolicy in
  their credentials-file or IAM policy did nothing; only the bucket's policy is
  now set aside, so a lockout can still be undone.
- **A user's name is no new user's while a bucket names it its owner.** A
  bucket records its owner by user name, so once that user was deleted, renamed
  or removed from the credentials file, an invitation or a CreateUser of the same
  name made a user with full control of the bucket; CreateUser, invitations and
  UpdateUser now refuse such a name with EntityAlreadyExists until the bucket is
  gone.
- **No rename makes a user named `socketley`.** UpdateUser's NewUserName was
  checked against the IAM and credentials-file users only, so a delegate allowed
  UpdateUser on `user/*` could rename itself to the default owner's name and own
  every bucket made with the default key; it is now EntityAlreadyExists, as
  CreateUser and invitations already were.
- **A Signature Version 2 presigned URL signs every subresource it carries.**
  A subresource added under an escaped name, `%76ersionId` or `%61cl`, was
  left out of the string to sign but read by the handler, so a presigned GET
  could be turned into a read of an old version or a `response-*` override,
  and a PUT into an ACL, tagging or part upload; it now breaks the signature.
- **A storage interface cookie does not renew itself under `--anonymous`.**
  `POST /~ui/session` with only a cookie and the interface's header, which
  `--anonymous` let past the check for credentials, set a fresh cookie of 12
  hours or 30 days that signing out of the old one did not end; a cookie is
  now set only for a sign-in made with credentials.
- **A refused interface cookie no longer blocks the identity provider's
  sign-in.** A storage with `--idp` answered a request carrying a `skl_ui`
  cookie it refused, one left from before signing out everywhere, of a key
  since changed, past its expiry or tossed from a sibling host, by that
  refusal alone, and the browser went round the idp's sign-in for good; the
  idp's session is now asked next, and the refusal stands only without one.
- **A folder is not copied or moved onto its own bucket's root.** WebDAV's
  COPY or MOVE of `b/a/` to `/~dav/b/` was let through where any other folder
  above it was refused, and wrote `b/a/x` over `b/x` before the walk had read
  it, losing what was there; it is now 403 like the rest.
- **A library deleted with its contents is judged file by file.** `DELETE
  /~dav/<bucket>/?contents` asked a policy only about the bucket and one key
  standing for all, so a Deny on deleting a prefix's objects was passed over
  and they went with the bucket; each version is now judged as its own
  DeleteObjectVersion, and one refused keeps the library, answered 409.
- **Another site cannot act through the Basic credentials a browser keeps.**
  Only a change signed by the webmail's cookie had to carry its header, so a
  form on any site, posting `text/plain` JSON to `/jmap/api`, was signed by
  the password the browser had cached for the JMAP or DAV prompt and set a
  vacation reply, a signature or a mailbox; a form's body, a cross-site
  navigation and a cross-site call whose body is not `application/json` are
  now 403 whatever signs them.
- **The webmail's hidden images stay hidden.** An image URL was judged
  remote only by a leading `https://` or `//`, so `&#1;https://...`,
  `\\host/...` and a `//` split by a newline, which the browser reads as
  remote, and an SVG `<animate>` of an `href` loaded a tracking pixel with
  images off; URLs are now read as the browser reads them, SVG animation is
  removed, and the message's frame refuses images not of the webmail while
  they are blocked.
- **A References header of millions of ids makes a hundred strings.** An
  APPEND or a delivered message of 25 MiB of `<a>` built a string for every
  id on the loop, about 0.8 GB, to keep the first, and SORT and THREAD kept
  each message's room for all of them until they answered; the thread's root
  is now the first id read, and SORT and THREAD keep the last hundred.
- **Asking for another user's folder makes no index for them.** Any
  `Other Users/<name>/...` a signed-in IMAP user named wrote a lock and a
  journal for `<name>` and kept it in memory and in every tick for good, so
  a client naming millions filled the state volume and the shard; an owner
  without an index now has given no rights and gets none made.
- **IMAP LIST takes at most 64 patterns of 1024 bytes.** Every folder was
  matched against every pattern with the reference copied in front of it
  each time, so one LIST of a 25 MiB reference or of millions of patterns
  held the shard's loop for minutes; such a LIST is now BAD, a pattern stops
  at the first character it cannot match, and a command of more than a
  million words is refused.
- **A cache's glob is linear in what it is given.** KEYS, SCAN MATCH,
  VALUEMATCH and pattern subscriptions backtracked once per subject byte, so
  `KEYS *<128 KiB of a>b` against a 256 KiB key held the shard for tens of
  seconds. A plain run after a star is now placed at its first occurrence and
  the last one is compared with the tail; a pattern that would still cost more
  than about 64 steps per byte of pattern and subject matches nothing there.
- **A script cannot give KEYS or ARGV a metatable.** The two tables are
  shared by every EVAL on a cache, so a metatable one client's script set on
  them ran in every later script until a restart, answering its reads and
  catching its writes; `setmetatable` on either now raises.
- **A readonly cache refuses PUBLISH over RESP too.** It answered
  `denied: readonly mode` over the text protocol and delivered the message over
  RESP, from a client or a script's `redis.call`; it is now `-ERR readonly mode`
  on both.
- **A tunnel edge's idp is beside it only within one registrable domain.**
  `tunnel connect`, `ssh` and `join` handed a kept sign-in to the idp an edge
  named whenever the two shared a parent label, so `evil.duckdns.org` could
  name `https://home.duckdns.org` and be sent its token to replay there; the
  two names must now be one registrable domain by the Public Suffix List, and
  without the list only the edge's own name is trusted without `--idp`.
- **A tunnel service's hashed socket is no longer in `/tmp`.** Where the state
  directory is too deep for a socket's path, an edge served the service on
  `/tmp/skl-<hash>.sock`, which another local user could bind while the edge
  was stopped and then receive every visitor's request, cookies and bearer
  tokens with it; it is now `<daemon socket>.rt/tunnel-<hash>.sock`, in the
  0700 directory of this user's that companion nodes use, and a service with
  no such path is not served.
- **`export` writes no file after a runtime name that is a path.** It named a
  runtime's file, its comment and its `include` line after the name the socket
  answered with, so a listener there that named a runtime `../../x` had the
  export write outside its directory; a name no runtime may have is refused.
- **No command goes to a daemon socket held by another user.** Every command
  the CLI sends now asks the socket's peer who it is first and refuses one
  that is neither this user, root nor the packaged daemon's account; `--lua`
  and `export` also skipped the probe the other verbs make, so a listener at
  the shared `/tmp/socketley.sock` read every flag `--lua` makes runtimes
  with, `--master-pw` and `--secret-key` among them. `socketley daemon`
  reports such a socket instead of exiting 0.
- **A running runtime's trust is not edited behind its back.** `edit
  --client-ca`, `--client-cert` and `--client-key` on a running proxy, and
  `--ca` or `--tls` on any running runtime, were stored, shown by `show` and
  answered with success while the listener and the backend leg went on with
  the context they started with, so a client CA rotated after a compromise
  kept letting the old certificates in until a restart nobody was told to
  make; they are now refused while it runs, in `edit` and in `import`, and
  `--restart` takes them. Naming the value it already has is no change.
- **`export --full` keeps the setup's secrets to itself while it works.**
  The Lua setup it writes beside the data, every runtime's master password
  and keys in plain text, went into a `.export-<pid>` directory of the state
  directory at 0755, readable for the whole archive write where the state
  directory can be traversed and left there for good by an export cut short;
  the directory is now 0700 and the next export removes any whose process is
  gone.
- **`export --full` writes no archive through a link beside it.** The
  archive was written to `<file>.partial`, opened through a symlink or into a
  file someone else left at that name, so a root export into `/tmp` could
  hand the whole state, passwords and keys to another user or overwrite any
  file; it now goes to a name of its own export's process, made new and never
  followed.
- **Restore writes no file through a link at its scratch name.** Each file
  went to `<file>.restore-tmp` opened through whatever stood there, so an
  archive whose earlier entry was a symlink of that name had root write the
  next file's bytes wherever the link pointed; the name is now removed and
  made new, never followed, and an archive that holds such a name, which
  export never writes, is refused.
- **Restore writes no system file an archive names.** `socketley restore`
  took every root its archive's manifest listed as a place to write, so a
  crafted archive restored as root could put a file in `/etc/cron.d`,
  `/etc/sudoers.d` or `/root/.ssh`; it now writes this machine's state and
  config directories, and other roots only outside `/etc`, `/usr`, `/root`,
  `/boot`, `/run`, `/var/spool` and the like and outside a home's hidden
  files, saying what it leaves. No restored file keeps a setuid or setgid
  bit, and outside the state and config a file the archive says root owns is
  written as the daemon's user's.
- **An MQTT client that does not read stops being read.** WebSocket pongs,
  PINGRESPs and acks were queued for a client whatever it had left unread, so
  one sending pings and reading nothing grew the broker's memory at line rate,
  before CONNECT for 10 seconds and after one with keep alive 0 for good. Past
  twice `--write-buffer` unread, a connection is not read until it has taken
  half of it.
- **An MQTT WebSocket frame is held only up to four times `--max-packet`.**
  An unfinished frame was kept whole up to WebSocket's 16 MiB however small
  `--max-packet` was, before any CONNECT and, after one with keep alive 0,
  for good. One longer now closes the connection, counted as a WebSocket
  refusal.
- **`--rrl` holds for a sharded dns runtime as a whole.** Each shard kept the
  full limit for itself, and the kernel spreads a forged flood over the shards
  by source port, so `--shards 8` let eight times `--rrl` through to one
  network. Each shard now allows its share.
- **A DNS TCP connection is kept by whole queries, not by bytes.** Any byte
  read counted as activity, so a peer sending one byte of a query it never
  finished every few seconds kept its connection for good, and 256 of them
  closed every new TCP client of a shard at once. Only a whole query or a
  write counts now, and a full table closes its quietest connection with
  nothing left to write to make room for the new one (`tcp_evicted`).
- **A DNS TCP peer that does not read its answers stops being read.** A
  connection's queries were read and answered however many answers waited
  unsent, up to 256 MiB a connection, and one with answers waiting was never
  closed. Past 64 KiB unsent its queries now wait unread, and a connection
  whose answers have not moved for 30 seconds is closed.
- **A sync brings, renames and removes files only below `--dir`, whatever
  its folders are links to.** One way in, a conflict on a file reached through
  a folder linked out of `--dir` renamed the file at the far end of the link
  aside, outside it, before the copy was refused; the folders a file is
  placed in, renamed in or removed from are now opened by the kernel below
  `--dir`, and a file reached through a link out of it is left alone.
- **An `--exclude`d folder keeps its whole tree out of a sync both ways.** The
  walk never entered it, but a key the storage listed below it was judged by
  its own name only, so under `--exclude .git` an `a/.git/config` put in the
  bucket was brought into `--dir`, a command the next `git status` there would
  run; every folder on a path is now held against the patterns, as is the
  job's own `.socketley-sync`.
- **A server's WebSocket takes a browser only from its own pages and the
  `--origins` it lists.** Any web page could open `ws://` to a server its
  visitor could reach, one bound to 127.0.0.1 or behind a firewall included,
  and read and write its linked cache through that visitor's browser. An
  upgrade whose `Origin` is neither the `Host` it was sent to, the
  `X-Forwarded-Host` of a proxy in front, nor in the new `--origins` list
  (`*` for any) is now 403; a client that sends no `Origin` is not affected.
- **Every line forwarded to a master carries its sender.** With `--send-to
  master`, a WebSocket client's one message could hold line breaks, so a raw
  TCP master read `[7] hi` and then a `[4] ...` line that client had written as
  if another had sent it; each line of a forwarded message now starts with the
  real sender's descriptor.
- **A client id that begins with `$` takes nothing from an ACL pattern.** Under
  `pattern read %c/#`, a client that connected as `$SYS` was granted `$SYS/#`
  and read the broker's figures; a `%c` or `%u` that would open the filter with
  `$` now grants nothing, and a deny with it holds for everything.
- **An account's sign-ins end everywhere when it does.** Disabling an account,
  signing it out everywhere, a new password, a reset or removal from `admins`
  now ends its cookies and tokens at every runtime that takes the idp's
  sign-ins (proxies, storage, the dashboard, tunnel edges) within a second,
  where they held until they ran out, up to 30 days; the admin bit is the
  account's now, not the one the cookie was signed with.
- **AssumeRole of a role nobody made is NoSuchEntity.** Any RoleArn that
  named no role the IAM API made gave the caller a session of its own, as if
  the role had been assumed; it is now refused.
- **A Signature Version 2 presigned URL lasts at most a week.** Its `Expires`
  could lie any distance ahead, so such a URL never ended; one more than seven
  days ahead is now refused, as a Version 4 one is.
- **Every `x-amz-*` header must be signed.** Signature Version 4 required
  only host, the date and the payload hash among the signed headers, so anyone
  holding a signed request or a presigned URL could add `x-amz-copy-source`,
  object-lock or SSE headers to it. A header the signature does not cover is
  now 403 AccessDenied, as in S3.
- **A replica's status is taken only from a replication.** Any client could
  send `x-amz-replication-status: REPLICA`, be judged for ReplicateObject
  instead of the write and so escape a Deny of it, and name a replica version
  id that made the key's next version id wrap. The header now counts only for a
  user allowed the replication action and not denied the write, and a source's
  version id is kept only while it is no more than fifteen minutes ahead.
- **A share link gives only what its maker may still do.** A folder link was
  judged once, as a ListBucket, and then read every file under it, and any link
  went on working after its maker lost access, was disabled or removed, or its
  bucket was removed and made again by someone else. Each read is now its
  maker's GetObject of that key, an upload its PutObject, a folder's page and
  ZIP its ListBucket, judged at the request; a link is bound to its bucket's
  owner and creation time.
- **An object runs nothing on the web interface's origin.** An HTML, SVG or
  XML object, read by S3, anonymously or through a share link, was shown inline
  on the origin the web interface is served from, so its script acted with the
  reader's session. Every object answer outside a website endpoint now carries
  `nosniff` and a sandboxing Content-Security-Policy, a type a browser would
  run is sent as an attachment, and an anonymous GET takes no `response-*`
  override.
- **A head arriving in small pieces is scanned once.** Each read of an
  unfinished request head searched it again from its first byte, so a head sent
  a byte at a time cost the square of its length; the scan now resumes where
  the last one stopped.
- **HTTP/1.0 with Transfer-Encoding is refused.** The proxy forwarded such a
  request as it came, though a 1.0 backend may read no chunks and take the body
  for the next request (RFC 9112 6.1); it is now answered 400.
- **An absolute-form request names one host.** `GET https://A/x` with
  `Host: B` was routed and checked against the TLS name by A and reached A's
  runtime telling it B; HTTP/2 the same with a `:path` of `https://A/x`. Such a
  request is now refused 400, and an HTTP/2 `:path` must be origin-form, or `*`
  for OPTIONS.
- **A proxy's X-Forwarded-For always names the client.** A client that reset
  its connection right behind its request left no address to look up when the
  request was read, and the empty address stood for a local unix peer: the
  client's own X-Forwarded-For reached the backend with no hop added, and
  `--auth` took it as the client's address. The address is now read at accept,
  and a TCP client without one is refused.
- **A DMARC policy is read before the names a sender chose.** The From
  domain's record was looked up last, after SPF, up to ten DKIM keys and the
  ARC keys of the sender's naming, so a sender whose nameserver left those
  unanswered spent the check's 20-second budget, the policy lookup failed as
  `temperror`, and mail forged under a `p=reject` domain was delivered; the
  record is now read first.
- **DMARC's `pct=` sample is not the sender's to pick.** It was an unkeyed
  hash of the Message-ID, so a sender forging a domain that published
  `p=quarantine; pct=10` chose an ID outside the sample and reached the inbox
  every time; the hash is now keyed by a secret of the runtime's process.
- **An ARC seal this runtime adds says `cv=pass` only for a chain that
  passed.** The newest seal's `d=` was copied into the Authentication-Results
  unchecked, and the seal put on forwarded mail took `cv=pass` from any
  `arc=pass` in that text, so a broken chain sealed `d=xarc=pass` was sealed
  on as passing under this runtime's key; a sealer that is no domain name is
  now left out, and only this host's own `; arc=pass (i=` token counts.
- **A share taken back ends in the sessions that have it selected.** Rights
  were read once, at SELECT, so after DELETEACL a grantee who kept the folder
  open went on reading, searching, flagging and expunging the owner's mail
  for as long as the connection lasted, and IDLE kept telling its changes; each
  command now reads the rights again, a folder without `r` is closed with
  `[NOPERM]`, and one left without a right to change anything is read-only.
- **Only a mailbox's owner names its imapsieve script.** A user given `w`
  on another's folder could set `/shared/imapsieve/script` to one of the
  owner's Sieve scripts, which then ran as the owner on every message the user
  flagged, filing, discarding or redirecting the owner's mail; the entry is now
  `[NOPERM]` for anyone but the owner.
- **RCPT after a BDAT chunk is refused.** A recipient named between chunks
  was answered 250, under LMTP with a 250 of its own at the end, but the
  message had taken its recipients with the first chunk and never reached it;
  it is now 503, as DATA after a chunk already was.
- **An SRS address's hash binds where its host ends.** It covered the stamp,
  host and local part run together, so the address made for
  `ictim.orgbob@v` also passed as one for `bob@victim.org`, and a bounce
  address could be had for a recipient of the sender's choosing; the parts are
  now hashed with the `=` between them, and a host holding `=` is not
  rewritten.
- **A no-reply bounce suppresses only the address the mail went to.** The tag
  in `no-reply+<tag>@` was a hash of the recipient's domain alone, the same for
  every recipient there and for ever, so anyone sent one no-reply message could
  read it from their Return-Path and bounce every other address at their
  provider into suppression for ninety days. no-reply mail now goes one
  recipient a transaction under a tag of that address and the day, taken back
  for seven days; a bounce under a tag sent before this release suppresses
  nobody.
- **SRS addresses carry a 40-bit hash, and SRS1 ones expire.** The hash was
  four base64 characters compared without case, about 21 bits; it is now eight
  base32 characters, an SRS1 address is refused once the first forwarder's day
  stamp inside it is 21 days old.
- **The four-character SRS hash is not read back at all.** It was still
  taken until 2026-12-31 for addresses no release wrote, so a million
  unauthenticated RCPT probes found a bounce route through this host to any
  address; only the eight-character hash is now an SRS address.
- **The webmail port takes X-Forwarded-For only from 127.0.0.1 or ::1.**
  Another peer could name a new client with each failed sign-in and never be
  locked out; its failures now count against its own address.
- **The webmail's message CSS can no longer end its `<style>` or load a
  blocked image.** `</style` was removed in one pass, so `</</stylestyle>`
  left one, and only `url(` was blocked, so `image-set("https://...")` loaded
  a remote image; CSS is now unescaped, keeps no `<`, and every function that
  loads an image is dropped while images are blocked.
- **Only CRLF.CRLF ends a message's DATA.** A bare LF began a line the
  ending dot could open, so `\n.\r\n` ended the message and what followed ran
  as commands (SMTP smuggling); a bare LF is still written as CRLF, but a dot
  after it is data.
- **A stranger's mail sent on by an alias or a redirect is not DKIM-signed.**
  Any outgoing message whose From named a local domain was signed with its
  key, so mail forged as `ceo@<domain>` and forwarded left signed; only mail of
  a signed-in user, of 127.0.0.1 or ::1, or that the runtime wrote is signed,
  and forwarded mail from elsewhere is ARC-sealed instead.
- **JMAP sends only a message whose From is the user's own.**
  EmailSubmission/set compared only the envelope's sender with the user's
  addresses, so a draft `From: ceo@<domain>` was sent and signed; its From
  header is now held to the check SMTP submission makes.
- **A submission whose header runs past 64 KiB is refused.** Only the first
  64 KiB of a signed-in user's header was kept for the From check, so a From
  of another placed after it was sent signed with the domain's key; such a
  message is now refused with 552.
- **A `From :` header is an author to DMARC and to submission.** DMARC
  counted only lines beginning `From:`, so `From : ceo@<domain>`, the author
  every reader shows, got dmarc=none and no policy, and a second From written
  so slipped past the two-From refusal and a user's submission check; every
  From header is now found by the name rule readers use.
- **socketley builds against liburing 2.7 to 2.9 again.** The loop's I/O
  wait opt-out is a liburing 2.10 call and is now left out of an older build.
- **An ignored `SOCKETLEY_NAPI_BUSY_POLL_US` is reported.** A kernel that
  refused NAPI busy poll left the setting doing nothing without a word; the
  loop now logs a warning.
- **A 5.19 or 6.0 kernel keeps its ring flags.** Without the flags that
  need 6.1 the loop fell back to a ring with none, losing SUBMIT_ALL, so one
  failing submission held back the rest of its batch; a middle tier keeps
  SUBMIT_ALL, COOP_TASKRUN and the larger completion queue.
- **Connections are read on a 5.19 kernel.** Multishot receive needs 6.0
  but was turned on wherever the receive opcode existed, so on 5.19 every
  runtime closed each connection at its first read; it is now probed for real,
  and a refusal the probe missed turns it off and re-arms a plain read.
- **No user takes the buckets' default owner.** An invitation or CreateUser
  could make a user named `socketley`, the owner every bucket with none
  recorded belongs to, and so own all of them; the name is refused.
- **An e-mail a user gives themselves is no longer taken as theirs.** The
  account page saved any `email`, and a mail runtime let the user send from it
  and sign in by it, so a user setting `ceo@<domain>` sent as the CEO. An
  e-mail is now a plain address; one its holder sets may not be another
  account's, nor `<another username>@` a domain of the provider's or one an
  admin gave an address in; and only one an admin set with `idp-user`, or the
  account's own `<username>@<issuer host or cookie domain>`, is vouched for:
  only that one is in the session cookie, the mail runtime's answers and an
  address's lookup, and tokens carry `email_verified`. An e-mail set before
  this release is vouched for only once an admin sets it again with
  `idp-user <idp> set <user> email=...`.
- **A sign-in or an account's change posted from another site is refused.**
  POST /login, /authorize, /device and the /account forms answer 403 when
  Origin, or else Referer, names a page that is neither the provider's nor
  under its cookie domain, so another site cannot sign its visitor into an
  account of its choosing; a client sending neither header is taken as
  before. The provider's pages now say `Referrer-Policy: same-origin`, under
  which a browser posts their forms with their Origin.
- **A return address with a backslash in its host is refused.** With
  `--cookie-domain` set, `rd=https://evil.example%5C.example.com/` passed as a
  name under the domain, and a browser, reading the backslash as a slash, went
  to evil.example after signing in or out; a return address's host may now hold
  only letters, digits, `.-_` and a port.
- **Allowing a device says what it allows.** The idp's `/device` page asked
  to allow a code with no word of which application asked or that it could
  get SSH certificates, as root for an admin, and the address `socketley
  login` prints filled the code in, one click from allowing it. The code now
  leads to a page naming the application and what it may do, and a client
  marked `ssh` is allowed only with the password, or the code, given again.
- **Refresh tokens are good once, and SSH certificates want a recent sign-in.**
  A refresh left the old refresh token valid, so a stolen one went on working
  beside the owner's; each refresh now gives the next and a token used again
  ends its sign-in. `/ssh/user-cert` gave a certificate on any refreshed token;
  it now wants a sign-in of the last twelve hours. Refresh tokens given before
  this change are refused once, and `socketley login` signs in again.
- **An authenticator code signs in once, anywhere.** The idp remembered the
  last code taken in each shard's memory, so the same code signed in again at
  another shard or after a restart; the step is now kept with the account and
  taken at shard 0 only while it is still the last one there.
- **Sign-in guesses are bounded at every turn.** The idp counted a failure
  only once its hash was done, so guesses sent together from one address
  were all checked; it now counts those in flight, an IPv6 address by its
  /64, holds an account up after ten failures from anywhere (half a minute,
  doubling to five, never for a browser it signed in on), ends a second step
  after three wrong codes, and lets at most 64 checks wait.
- **SSH user certificates permit less.** A certificate the idp signed
  permitted X11 forwarding and the user's `~/.ssh/rc` beside a terminal, port
  and agent forwarding, root ones too; it now permits only the last three.
- **A forced password reset asks for the second step first.** Setting a new
  password without a session took a username and the old password alone and
  signed the account in, skipping its authenticator code, and for any account,
  not only one told to reset. The reset page now comes only after the password
  and the code, and carries a token of that sign-in, used once; the return
  address a sign-in ends at is checked wherever it ends, and a Location with a
  control character is refused.
- **Clients are closed beside an idle connection on older kernels.** On a
  kernel that frees io_uring's file nodes in order (6.8 here), one idle
  connection to a cache or a server, a replica's included, left every client
  closed after it in CLOSE-WAIT with no FIN sent; such a kernel is now found
  at start and those runtimes use plain descriptors there.
- **A script's `socketley.stop` frees the port before it answers.** A script
  running in the daemon left the stopped runtime's workers serving for up to
  two seconds, and an `edit --shards` and `start` in that time kept the old
  shards beside a new one, whose `self.clients()` and theirs each missed the
  other's clients.
- **Tunnel names and joins, made safe.** A kept sign-in goes only to an idp
  beside the edge that names it, so an edge cannot ask for another's token; an
  agent that has joined is replaced only with `tunnel join --replace`; an
  admin reaches an agent's TCP service only where the edge opened it; a name
  is routed once an agent has joined, and two edges' services of one name do
  not share it; a service's auth with an empty method or a `#` is refused, and
  an edge serves no service whose auth it cannot read.
- **The dashboard while a runtime is edited.** A dashboard page or an alert
  check that read a runtime's certificate, address or socket path while
  `edit` or `import` changed it could read freed memory and crash the daemon;
  the two now take turns.
- **A tunnel's TCP service on one address.** `--tcp ssh:127.0.0.1:2201` opens
  the port on that address alone, for a service only `tunnel ssh --agent`
  reaches, where every TCP service was opened on all of them.
- **ssh to a machine at home.** `socketley tunnel ssh <edge> --agent pi` as ssh's
  `ProxyCommand` reaches the agent pi's `ssh` service through port 443, for an
  admin of the edge's idp; `tunnel connect <edge> pi/<service>` any TCP service
  of an agent. Nobody else may name one.
- **A tunnel service with more than one way in.** An HTTP service's auth may
  join several with `+`, `ollama=idp:auth+bearer:/etc/socketley/hub.token`:
  a person signed in and a program with the token both get through, and a
  browser with neither is sent to sign in. The edge's log names who the
  entrance heard an agent or a person from, where it said the entrance.
- **A tunnel's settings by `edit`.** `socketley edit <agent> --offer ... --restart`
  changes what an agent offers, and so for every tunnel flag; without
  `--restart` a running tunnel says it needs one, where it said unknown flag.
  An edit refused on any of its flags leaves every tunnel setting as it was,
  and with `--restart` the tunnel starts again unchanged.
- **Installed, and usable without sudo.** `scripts/install-from-source.sh`
  adds who runs it to the `socketley` group, so after logging in again
  `socketley` commands reach the daemon without `sudo`.
- **Guessed client secrets bar the address.** Five wrong client secrets at an
  idp's token endpoint from one address in a quarter of an hour bar it there,
  as five wrong passwords already did at the sign-in page.
- **Access tokens are for the application they were given to.** A db, mail
  or mqtt runtime with `--idp` takes an access token only from a client
  `--idp-audience` names; a token the provider gave any other application
  is refused and said once in the log. Without the flag no access token is
  taken, and cookies and passwords sign in as before.

### Added

- **UDP through a tunnel.** `tunnel <edge> invite|set <agent> --udp
  <name>:<port>` and `tunnel join ... --udp <service>:<port>=<host>:<port>`
  open a UDP port on the edge whose visitors' datagrams the agent carries to a
  service at home and back, each visitor a flow of its own, for a game server
  or anything else that speaks UDP; a datagram is dropped rather than queued
  while the agent is away or its link is full, and the metrics count both.
- **An SSH certificate is revoked now, not at its expiry.** `socketley
  idp-ssh <idp> revoke <user>|<serial>` ends a person's certificates at once,
  through the revocation list `idp-ssh <idp> krl` names for sshd's
  `RevokedKeys` (and `/ssh/krl` serves); signing out everywhere, disabling,
  resetting or removing an account, or changing its groups, revokes them too.
- **`socketley tunnel share <edge> <port>` shows a port of this machine at a
  name the edge gives.** Six letters and digits beside the edge's own name, for
  those signed in at its idp or with `--public` for everyone, until Ctrl+C,
  two hours unless `--for` says otherwise, or the sign-in ends; for admins of
  the edge's idp, three at a time.
- **64-bit ARM.** socketley builds on aarch64 as on x86-64: the makefiles are
  for the machine premake runs on (`release_arm64` there), Release compiles
  for every 64-bit ARM CPU, `scripts/install-from-source.sh` builds premake
  itself where the x86-64 `bin/premake5` cannot run, and a package built
  there is an `arm64` .deb that `install.sh` picks on such a machine.
- **A code to scan for two-step sign-in.** An idp's page that turns two-step
  sign-in on shows the authenticator key as a QR code beside the key itself.
- **A tunnel runtime.** A machine with no address of its own — at home behind a
  router or carrier-grade NAT — runs a tunnel `--mode agent` that dials out to a
  tunnel `--mode edge` on a machine the internet reaches, over TLS on port 443
  through the entrance, and holds that one connection. The edge serves the
  agent's HTTP services under names beside its own — `ollama.example.com` for
  an edge `edge.example.com` — routed by the entrance with its certificate and
  answered by the dns runtime, a name a runtime has staying that runtime's, and
  its TCP services on ports of their own; nothing is opened on the router.
  `socketley tunnel join <edge> --http ollama=127.0.0.1:11434` on the machine
  at home is all it takes: an admin of the edge's idp, signed in for that join
  alone by a code allowed in a browser and kept nowhere, adds the agent, and the agent runtime is made and
  joins, its services asking visitors to sign in. Without an idp,
  `socketley tunnel <edge> invite` prints an invitation the agent joins with
  once, in exchange for a key of its own; `set` changes what it offers,
  `revoke` cuts it off. An HTTP
  service invited as `<name>=<auth>` asks every request of its visitors for what
  a proxy's `--auth` takes — a sign-in at an idp, a token or a key — before any
  of it reaches home; the figures are in the metrics as `socketley_tunnel_*`. An
  edge with `--forward` carries a person signed in at its `--idp` to the targets
  it names: `socketley tunnel ssh <edge>` as ssh's `ProxyCommand` reaches a
  server through port 443, signed in at the idp the edge names. It takes the access tokens of the client
  `socketley login` signs in as, `socketley`, unless `--idp-audience` names
  others.
- **SSH by the sign-in.** An idp runtime with `--ssh-ca <hours>` is an SSH
  certificate authority: `socketley login <idp>` signs a person in from the
  command line by a code they allow in a browser (the device grant, RFC 8628,
  as the client `socketley`, marked `device` in `--clients`), `socketley ssh-cert <idp>`
  then gets a certificate for their key that holds that many hours and names
  their username, `root` for the admins group and each `ssh:<name>` group,
  and sshd takes it with `TrustedUserCAKeys`. `socketley idp-ssh <idp> ca`
  prints the authority's key, `host-sign` certifies a server's host key for
  `@cert-authority`. Only a client marked `ssh` may ask, a disabled account
  gets nothing, and every certificate is said in the log.
- **Every sign-in in the log.** An idp runtime says who signed in, how and
  from where, and who allowed or refused a device.
- **A machine whole, data and all.** `socketley export --full <file>`
  writes the setup and every runtime's data into one tar archive (gzip,
  `--compress best` for gzip -9's effort, or `none`, compressed on every
  CPU or `--threads N`): the state directory,
  the configuration, the storage buckets, mailboxes, accounts and keys, a
  db by its own backup; `socketley restore <file>` puts it back on a machine
  whose daemon is stopped, and the runtimes come back as they were.
- **DNSSEC.** A dns runtime with `--dnssec` signs its zones as it loads
  them (ECDSA P-256, an NSEC chain, an RRSIG over every set), answers a
  query with the DO bit with the signatures and the proofs of what is not
  there, and signs again before the signatures end; `socketley dnssec <dns>`
  prints the DS record for the registrar.
- **Calendars and contacts.** A mail runtime with `--idp` and `--storage`
  serves CalDAV and CardDAV on its JMAP and webmail ports: every user has a
  calendar and an address book at `/dav/<user>/`, makes more, and syncs them
  with Thunderbird, DAVx5, iOS and macOS, found through `/.well-known/caldav`,
  the Apple profile, Thunderbird's autoconfig and the `_caldavs` and
  `_carddavs` records. The entries live in the storage bucket beside the
  mail.
- **A mailbox moves.** `socketley mail export <user> [dir]` writes a user's
  folders out as mbox files, a folder each, the flags as Status and
  X-Status and the keywords as X-Keywords; `socketley mail import <user>
  <file.mbox|dir>` reads them back, or Thunderbird's, or a Google Takeout's
  into the folders its labels say, read and starred as its flags. Both wait
  for the end and say how many messages went.
- **The webmail does what a mail client does.** Drafts save as they are
  written; a send can be undone for a few seconds or put off until a time;
  a message can be archived, printed or shown with its headers; a whole
  folder is selected or emptied; the editor writes formatted text; a user
  with more than one address sends from any of them, and a reply goes out
  from the one the message was sent to; the out-of-office answer takes two
  dates; filters for arriving mail are written as a Sieve script; and new
  mail is told while the tab is in the background. It speaks German where
  the browser asks for it.
- **IMAP and JMAP extensions.** IMAP has WITHIN (OLDER, YOUNGER), SAVEDATE,
  PREVIEW and AUTHENTICATE LOGIN; JMAP has Quota (RFC 9425) and
  Identity/set.
- **Signing in, defended.** An idp account can have a second step
  (`idp-user <idp> totp <user> on`, or on the account page): a web sign-in
  then asks the code an authenticator app shows, once, and mail apps sign in
  with app passwords (`idp-user <idp> app-password <user> add <label>`), each
  taken back on its own. SMTP, IMAP and POP3 take the idp's tokens by
  XOAUTH2 and OAUTHBEARER. Guesses spread over many addresses refuse the
  account to all but the addresses it signs in from, the refusals outlast a
  restart, and each sign-in is logged. Mail from elsewhere with an
  attachment that runs (`--refuse-attachments`, Gmail's list unless said)
  is refused, and `--clamav <host:port>` refuses what clamd names.
- **Mail clients set themselves up, and mail arrives better.** A mail
  runtime with `--web` and `--domain` answers `autoconfig.<zone>` and
  `autodiscover.<zone>` through the entrance: Thunderbird's
  config-v1.1.xml, Outlook's autodiscover (and its JSON lookup, with the
  SRV record), and for a signed-in user an Apple profile and the settings in
  the webmail. `--dmarc-policy none|quarantine|reject` and `--bimi
  <logo.svg>[,<cert>]` are published; advertisements carry `List-Id`; a
  provider's feedback report (ARF) from a sender SPF or DKIM vouches for
  unsubscribes the user who complained; a bounce whose status is 4.x.x or
  5.2.2 suppresses nobody; and the runtime says when its address's PTR does
  not name its host.
- **Running a mail server.** `socketley mail` takes no runtime name where
  there is one mail runtime; `mail trace <address>` says what became of the
  latest mail from or to it (delivered, deferred, bounced, refused, with the
  answer), each also a line of the log; `mail usage [user]` what mailboxes
  hold against their quota; `mail dns --check` which of the records the
  domains need this machine's resolvers have. `--autoexpunge 30d` empties
  Junk and Trash of mail put there longer ago, the time a message was filed
  now kept beside it. The metrics carry a mail runtime's figures
  (`socketley_mail_*`), and the alerts a queue that keeps a hundred
  messages and a blocklist of `--dnsbl` naming the runtime's own address,
  which `socketley mail` says as well.
- **A spam filter that learns from the users.** Without `--rspamd`, a mail
  runtime scores mail with a filter of its own (SpamBayes' chi-square of
  the words of the subject, the text and the HTML, the From's domain and the
  links' hosts), taught by what users move into Junk and out of it, or file
  into a folder of their own, over IMAP, JMAP and the webmail's Report junk
  and Not junk alike. Trained on 20 of each it scores every message as
  `x-spam-bayes` and puts one of 0.9 or more in Junk; `socketley mail
  learn <user>/<folder> --as spam|ham` teaches it a folder at once, and `stats`
  says what it learned. Every shard learns into a journal the first, which
  takes mail, folds into its file.
- **A mail runtime takes its entrance's certificate.** `--tls` with `--dns`
  and no `--cert` is the certificate the dns runtime's entrance keeps for its
  names, renewed there; one still to be written is waited for, mail taken on
  SMTP meanwhile and submission, IMAP and the TLS ports opened once it is
  there, so a new machine's mail runtime starts without being told where
  ACME keeps its files, and an export does not name them.
- **A machine's setup as Lua files.** `/etc/socketley/config.lua` may say
  its `runtimes` as well as its `daemon`, and `include "runtimes/mail.lua"`
  or `include "runtimes/"` (each `.lua` in name order) splits them into a file
  each; a relative path in them is beside `config.lua`. The daemon makes the
  runtimes it has not when it starts, so a new machine needs the files and
  nothing else run. `socketley --lua <file>` brings a running daemon to the
  files: it makes what is missing, tells a runtime what differs from what
  `create` would make (a setting no longer said is cleared) across a restart
  where it runs, and leaves one that is as said untouched. `socketley export
  <dir>` writes a running machine's setup that way, with its zones and
  handler scripts beside it and the files it reads but does not hold named,
  and reads it back to check that each runtime would be made as it is. Every
  flag of a type is a Lua key of its own name (`submission`, `mail_domain`,
  `queue_lifetime`), where a mail runtime and the ACME flags had none.
- **A `mail` runtime: a mail server for the domains of a dns runtime and the
  users of an idp runtime, its mailboxes in a storage runtime.** It takes
  ESMTP on 25 (PIPELINING, SIZE, 8BITMIME, SMTPUTF8, STARTTLS, AUTH, CHUNKING
  and DSN), and on `--submission`/`--submissions` only from a user signed in
  and only as their own address; mail from elsewhere is checked against
  `--dnsbl` lists, SPF, DKIM and DMARC, the organizational domain read off the
  Public Suffix List. A message is synced to a spool of 32 MiB segments before
  250 is answered, one fdatasync committing every message that ended while the
  last ran, and it goes on to the domain's MX, with DANE where DNSSEC signed it
  and MTA-STS where the domain publishes a policy, or to a `--relay`; what is
  refused for now is tried again until `--queue-lifetime`, and the sender gets
  the delivery status reports DSN asked for. With `--dns` it publishes MX,
  SPF, DKIM, DMARC and the SRV records of its ports. Mail for a user is filed
  by their Sieve script (fileinto, reject, vacation, imap4flags and more, kept
  with `socketley mail <name> sieve` or over ManageSieve on `--sieve`) into a
  bucket, bounded by their `mail_quota`, and read over IMAP4rev1 with IDLE,
  CONDSTORE and QRESYNC, SORT, THREAD, QUOTA and COMPRESS=DEFLATE from every
  shard, which share each user's UIDs through a journal. A search reads the
  text decoded, not the attachments, and only the messages a filter of their
  trigrams, made as each is stored, does not rule out: a word in none of 2,000
  messages is answered in 0.2 ms where reading them took 19, the first search
  too. `socketley send`, a
  script's `socketley.mail.send`, a storage's `mail://` notification target
  and `daemon.alert_mail` send through it. Measured against Postfix on this
  machine it took 7,140 messages of 1 KB a second from 50 clients to Postfix's
  2,654, and against Dovecot it answered eight clients' SEARCH in a tenth of
  the time.
- **Mail from a template, for each recipient of a source, and advertisements
  people can unsubscribe from.** `socketley send <mail> --template f.html`
  sends each recipient a message of their own, `{{name}}` filled from their
  values (`{{name|otherwise}}` where they have none, `{{{name}}}` unescaped in
  the HTML), the plain part written from the HTML. A template is Lua:
  `{{ expr }}` is any expression, `{% if %}` and `{% for %}` blocks run where
  they stand (a list from a db document walked into rows), `include("f.html")`
  puts in another, and `--lua f.lua` defines functions for them plus
  `on_recipient(r)`, to change or leave out a recipient, and `on_link(url, r)`,
  to rewrite each link; a template reaches no file and no process, its
  script does. The recipients are
  addresses, `idp:<idp>[/<group>]` (its accounts and their fields),
  `db:<db>/<collection>` (its documents) or `json:<file>`, `--set` gives
  values for all, and `--rate-limit` paces them (2 a second unless said, `300/m` a minute). Sending stops
  before the first when its message has a placeholder without a value or is
  refused, and skips a later one, unless `--no-check` lets them be empty; `--test` shows the first and
  `--test-to` sends it to one address. `--ad` marks an advertisement: one
  recipient each, never one who unsubscribed, with their own link where
  `{{unsubscribe}}` is or below, List-Unsubscribe with a mailto: and the
  one-click POST of RFC 8058, served by the webmail's port (its GET asks, so a
  link scanner unsubscribes no one); the token is the address with an HMAC
  under the runtime's key. `--inline` sends an image inside the message for its
  HTML's `cid:`. `socketley mail <mail>` alone sums the runtime up, `mail
  <mail> unsubscribed|resubscribe` keeps the list, and `socketley db-query`
  prints what a query of a db finds.
- **A webmail on the mail runtime.** `--web <port>` serves a mail client in the
  browser, and JMAP beside it, in plain HTTP on 127.0.0.1, and `--domain mail`
  has a dns runtime's entrance reach it under `mail.<zone>` with its TLS, as
  the storage interface and the dashboard are reached. It signs in through the
  idp runtime's session cookie, so one sign-in is every runtime's, and looks as
  the storage interface does: the mailboxes with their unread counts and a
  starred view, the messages a page at a time, a search over all of them,
  reading, writing, replying and forwarding with attachments, drafts, moving,
  flags and deletion, a name, a signature and an out-of-office answer, and new
  mail as it comes, with keys for each. A mailbox lists conversations, a row
  each with its people and its count, and a conversation reads as its messages
  in order, from every mailbox, the read ones folded and what each quotes
  hidden; a message's attachments come above its text. A message's HTML is cleaned and shown
  in a frame sandboxed without scripts, its remote images held back until the
  reader asks for them. A change the cookie alone signs needs the page's own
  header, the page's script runs by its hash alone, and behind the entrance a
  password is taken only over the HTTPS it forwarded and failed sign-ins lock
  out the client it forwards.
- **An `mqtt` runtime: a broker for MQTT 3.1, 3.1.1 and 5.0, on TCP, TLS and
  WebSocket.** QoS 0, 1 and 2, retained messages, wills, and sessions that keep
  a client's subscriptions and the messages sent to them while it was away,
  until it comes back or the session expires; of 5.0 also message expiry,
  topic aliases, shared subscriptions, request and response, user properties
  and reason codes. Clients sign in with a `--users` file (made with
  `socketley mqtt-passwd`), with an `idp` runtime's access tokens or not at
  all with `--anonymous`, and an `--acl` file in Mosquitto's form says who
  reads and writes what. `--routes` hands messages to a cache, a db, a
  storage, a server or another broker beside the subscribers, queued while a
  target is down; a storage's events and a script's `socketley.mqtt.publish`
  reach its subscribers. `--persistent` keeps sessions and retained messages
  across a stop and a killed worker, `--shards N` is one broker over N
  workers, and `on_auth`, `on_publish`, `on_subscribe` and `on_connect` let a
  script decide. `mqtt-pub`, `mqtt-sub`, `mqtt-sessions`, `mqtt-kick` and
  `mqtt-retained` reach it from the shell.
- **A `db` runtime: JSON documents for applications, owned by the accounts
  of an `idp` runtime.** Collections of documents at `/c/<collection>/<id>`,
  read with GET, replaced with PUT, changed in place with PATCH (`set`,
  `unset`, `inc`, `push`, `pull` on dotted paths) and removed with DELETE;
  each carries its version (`_v`, its ETag), which `If-Match` and
  `If-None-Match: *` hold a write to. Queries (`POST .../_query`) take
  conditions, a sort, a limit and a skip, and use the indexes the `--schema`
  file declares, `unique:` ones refusing a second document of a value; `POST
  /tx` makes many changes or none. The schema says per collection who
  reaches it: `private` (a key), `owner` (an account its own documents),
  `shared`, `public` and `catalog`. Who asks is a key from `--keys`, or an
  account of `--idp` by its sign-in cookie or an access token the provider
  gave one of its clients; a cookie write from another site's page is
  refused, and `--origins` names the pages a browser may call it from with
  CORS. A write is answered once it is on the disk, and a script reaches the
  documents as `socketley.db`. The idp's session verifier takes access tokens as
  `Authorization: Bearer` for it.
- **The `db` runtime holds more than memory, streams its changes, keeps
  copies and backups.** Documents live in segments on the disk, appended to
  and sealed at 64 MiB; memory holds where each lies, its figures and its
  index values, and a cache of those last read (`--cache`), and sealed
  segments mostly dead are merged off the event loop. No answer is given
  before what it rests on is on the disk, a read's included, and the newest
  segment is given its room ahead of its records, so a sync seldom carries a
  change of its size. A query whose order an index or an account's own
  documents already keep reads only as far as its page. `GET
  /c/<collection>/_feed` streams every change as a Server-Sent Event,
  numbered, to a reader who may see it, resumed with `Last-Event-ID`; `GET
  /_feed` streams them all to a key. A schema line's `ttl:<field>` gives
  documents a time to go. `--replicate <url> --replicate-key <file>` makes a
  runtime a copy of another database over http or https: a whole copy once,
  then every change with its own number, resumed across restarts of either,
  read-only until `--replicate` is taken away. `socketley db-backup` and
  `db-restore` write and take back one file of every document;
  `--backup-dir`, `--backup-every` and `--backup-keep` schedule them.
- **The `db` runtime on several cores.** `--shards N` serves a database from
  N worker processes on its one port: shard 0 writes the one log and every
  shard reads it from the same files as it reaches the disk, answering reads,
  queries and streams itself and sending shard 0 the writes. A shard takes in
  what shard 0 has made durable before it answers, so a read on any shard sees
  every write answered before it began; transactions, unique indexes, streams,
  replicas and backups hold as on one shard, and the number of shards changes
  across a restart with the documents as they are. On four cores GET answers
  2.5-3.5x and queries 2.3x what one shard does; writes, bound by one disk,
  stay as many.
- **An `idp` runtime: one sign-in, for applications, proxies, storages and
  the dashboard.** An OpenID Connect provider with its own accounts: each a
  fixed random id that every token names it by, and fields with no schema --
  a few the provider reads (username, password, groups, name, email,
  picture, disabled), every other one kept for the applications as it is, so
  a field they add needs no change and an older build keeps what it does not
  know. Changes are synced to a journal before they are answered and folded
  into a versioned snapshot. `socketley idp-user` adds, changes, disables,
  signs out and lists accounts and imports a storage's users with the
  passwords they have there; `/account` lets a user change their profile and
  password and sign out everywhere. It serves the code flow with PKCE,
  refresh tokens, discovery, its key as a JWKS, `/userinfo` and `/logout`,
  signed ES256 with a key kept in the state directory (refresh tokens, which
  only it reads back, HS256 under a secret made from that key), remembers a
  session or an access token it verified until it expires, and hashes
  passwords off the event loop, on as many threads as it has cores, up to
  four, each making up to four scrypt hashes at once with AVX2: the same
  bytes as OpenSSL's, and under load 2.4x the sign-ins on the same cores. Its sign-in is a cookie that a proxy's `--auth
  idp:<runtime>`, a storage's `--idp <runtime>` and `daemon.dashboard_idp`
  verify themselves against the published key: a browser without one is sent
  to sign in and back, a proxy's backend is told the account in
  `X-Forwarded-User` and `X-Forwarded-Preferred-Username`, which a client
  cannot send itself, a storage takes the account as its user of that name,
  and the dashboard its admins. It serves plain HTTP behind the entrance;
  `--tls` is refused. `--shards N` serves it from N worker processes on its
  one port: shard 0 writes the accounts and every shard reads its journal
  before it answers, so a change holds at every shard once it is answered; a
  code is redeemed at the shard that gave it, wherever the exchange arrives,
  and a failed sign-in counts against its address at every shard. Two shards
  on two cores give 1.6-1.7x the refreshes and single sign-ons of one.

- **A `sync` runtime, which carries a directory to a storage.** One runtime is
  one job, with its own line in `socketley ls`, its own figures, log lines and
  alert; `--shards` is refused, since the shards would share no socket and
  would write one index from several processes. `--storage` takes a storage
  runtime of this daemon and a bucket (`ui/photos`, whose port comes out of the
  map the daemon sends every worker), a host and a port, or an http or https
  URL -- more than one only with `--mode out`. A target that can never work is
  refused when the job is made: no bucket, a path before it, a bucket name S3
  would refuse, one named twice, a runtime that is no storage, and a `--dir`
  that holds the storage's own data or lies in it, which would carry every
  object back into itself. `--mode` is the server's and the client's three
  words, of which only `out` is carried so far. Between the walks `--every`
  asks for, inotify says which files changed: a file is carried once it is
  written and closed, and removed once it is deleted. A file above 512 MiB goes
  in parts of 64 MiB, so one above the 5 GiB a single request carries arrives
  at all; without TLS a file's bytes go to the socket by splice. Eight
  requests go to a target at once, which carried 20,000 small files to a local
  storage in 24 s rather than the 149 s of one at a time. Nothing is
  removed from the storage unless it is provably gone here: a walk that broke
  off, a directory it may not enter, a file excluded since and a directory that
  is suddenly empty -- a disk that is not mounted -- take nothing away. A
  refused or unanswered request is logged once while its reason stays the
  same, raised as an alert after three readings, and tried again thirty seconds
  later whatever `--every` says; the credentials file is read again at every
  walk. The index of what was carried checksums every record, so a crash costs
  carrying something again and never a file believed carried that was not; it
  belongs to one directory and prefix and begins again when either changes, is
  deleted by `socketley remove` and moves with a rename.
- **An argument with a space in it arrives as one.** The daemon's command line
  is split on whitespace and had no quoting, so `--dir "/home/me/My Photos"`
  arrived as `/home/me/My` and a stray `Photos`, refused as an unknown flag, and
  a configuration file refused any value with a space. The CLI now sends a space
  inside an argument as NUL, a byte no argv can hold, and the daemon puts it
  back after splitting; every command without one is sent byte for byte as
  before. A tab is still refused in a configuration file. It keeps an index of what it last carried in the state directory,
  written before the change it records is called done, so a file deleted here
  is taken off the far side and one that never arrived is sent; a record cut
  short by a crash costs that record alone.

- **`socketley git-sync` and `socketley ping` in the interactive help.** Both
  were dispatched by the CLI and documented in the manual, and neither appeared
  in `socketley-help.sh`, so a reader who ran it to see what the binary does was
  told it does not do them. A test now reads the verb table out of `cli.cpp` and
  asks the manual's COMMANDS and the help for each one.

- **The host's name alone opens the storage interface.** A browser asked for a
  storage runtime's root, which S3 answers with an XML refusal no one can read,
  is sent to `/~ui/`; a client, which asks for no HTML and carries a signature
  or a query, is answered as before. The dashboard shows each runtime the names
  an entrance sends it, as a link out to them, in its list and on its own page,
  and the Domains view no longer offers a wildcard as a page to open.

- **Dashboard: logs and domains.** Its Logs follow the daemon's recent log live,
  by runtime, level and text, and a runtime that failed says the last warning
  or error it wrote, with how often it was started again. Each worker's stderr
  goes through a pipe of its own that the daemon reads, passes on unchanged to
  its own stderr and keeps the last 10,000 lines of, named by runtime. Its
  Domains show every certificate a runtime serves (names, issuer, days left,
  self-issued or not, a wildcard waiting for the delegation, the last failed
  issuance), each entrance's routes to their runtimes, and the dns runtimes'
  zones, whose records it edits: checked as the runtime reads them before they
  are written, the serial raised when it was left alone.

- **Storage: users of their own.** A user signs in to the web interface with a
  name and password -- an IAM login profile (CreateLoginProfile,
  UpdateLoginProfile, DeleteLoginProfile, ChangePassword), kept as scrypt -- as
  well as with a key. The page's Account changes the password and manages the
  user's own keys, which every user may do to itself without a policy; an
  admin's Users makes, invites (a one-time link), disables, deletes and sets the
  quota, name, email and admin-ness of users, as IAM tags (TagUser) the runtime
  reads and the group `admins`. Sharing a library offers the users by name.
  Only an admin changes an admin.

- **The daemon says what is wrong.** A runtime that failed or keeps being started
  again, a certificate that ends within two weeks, a disk, the host's memory or
  a runtime's own limit nearly full, and a git repository whose last pull
  failed are raised as alerts, every ten seconds whether a page is open or not,
  shown on the dashboard with their history and posted to `daemon.alert_webhook`
  (Discord, Slack, Telegram or any JSON hook) once each, also across a restart.

- **The daemon's dashboard runs the daemon.** The page on `metrics_port` is new,
  in the storage interface's look, whose stylesheet and helpers it takes from the
  same binary: an overview of runtimes, connections, messages, bytes, CPU and
  memory over the last fifteen minutes, hour, six hours or day, kept by the
  daemon a point every ten seconds and across its restarts in `.history` of the
  state directory, `GET /api/history`; every runtime with its state and
  figures, filtered by type and name; and each runtime's configuration and
  stats. Signed in with an admin key of `daemon.dashboard_credentials`, it
  starts, stops, restarts, removes and reloads runtimes, edits one in a form of
  its type filled from `show` (or as JSON for `import`), and makes one from a
  form of every flag `create` takes for its type, the command shown as it is
  filled in. Commands go over the daemon's control socket as the CLI's do, and
  only the dashboard's verbs. The session is a sealed HttpOnly, SameSite=Strict
  cookie; five failed sign-ins bar an address for fifteen minutes; without
  credentials the page only shows, as before. `test_dashboard` holds the form's
  schema level with the create parsers: its first run found `--mode` missing for
  clients and caches.

- **Storage: git repositories kept in a library.** The page's new Git tab adds a
  repository by URL (a branch, `main` by default, or `*` for every one); it is
  pulled when added, whenever asked, and by itself every day, week or month as
  its Pull every says (never by default), and when anything
  moved its branch's files are written under `<name>/` of the library -- what
  changed, or the whole tree the first time -- and a git bundle of its history
  under `_backups/<name>/`, which `git clone` makes the repository from. Every
  bundle of the last day stays, then the newest of each of 14 days, 8 weeks and
  12 months. Runs are `socketley git-sync`, started with temporary credentials of
  the user who added the repository and writing through the runtime's own S3
  API, so that user's rights, quotas and versioning apply. A private repository
  is read with the user's GitHub token, sealed with a key only the user's secret
  derives and passed to git through its environment.

- **The entrance replaces a web server in front of everything.** A proxy with
  `--domain` is reached by its name through the entrance and serves under no
  `/<name>/` prefix: the path and the Host go to its backend as they came, and
  `X-Forwarded-Proto`/`-Host` from the entrance, a hop on this machine, are
  kept. `--auth bearer:<file>` and `--auth basic:<credentials file>` (the keys of
  a storage runtime's admins) answer 401 without the right answer, never pass
  the credentials on, and answer an address that failed five times in fifteen
  minutes 429 with `Retry-After` -- behind the entrance, the address it heard
  from. `--redirect-https [port]` answers 308 to the same URL over HTTPS, and a
  dns runtime whose entrance is on 443 makes one on port 80 beside it. The
  entrance over TLS adds `Strict-Transport-Security: max-age=31536000` where the
  runtime answering set none. Its certificate no longer waits for the
  delegation: `acme issue` asks the resolver for a TXT record only this
  daemon's dns runtime serves (`SOCKETLEY_ACME_DNS_PROBE` names another, or
  `off`) and then every name server of the zone directly, after
  `SOCKETLEY_ACME_DNS_WAIT`, as a CA asks any of them; a zone not delegated
  here yet, or with a secondary that has not caught up, has its names proven one by one
  over TLS-ALPN-01, the wildcard asked for again every six hours; asked again
  for what the certificate already holds, it does not trouble the CA. A zone
  file `--zone <name>` writes gives the zone's own name the entrance's address.
  The dashboard serves a request carrying `Via`, which no page can set, whatever
  its Host, and its pages are never framed, sniffed, cached or named in a
  Referer.

- **DNS: the names runtimes are reached by, published; wildcard certificates over
  DNS-01.** Every runtime takes `--domain name[,name]` (a storage runtime its own,
  which also names its buckets' virtual hosts). The daemon writes those names and
  the names of `--acme` into `state-dir/.dns/`, and a dns runtime given
  `--publish <addresses>` answers each one under its zones with this machine's
  IPv4 and IPv6 addresses: a name without a dot is taken under the zone, a
  storage runtime's comes with the wildcard its buckets are addressed under, and
  a runtime removed takes its names with it. What the zone file says of a name
  wins. `acme issue --challenge dns-01`, which a wildcard takes by itself, puts
  its answer in the same directory, served as the TXT record of
  `_acme-challenge.<name>`; `--acme '*.example.com'` is now taken. The serial a
  zone is served with grows with every change of these, so secondaries take them
  up. `SOCKETLEY_ACME_CHALLENGE` proves every name over another challenge and
  `SOCKETLEY_ACME_DNS_WAIT` (10 s) gives secondaries time before the CA looks.
  A wildcard certificate from Pebble was issued in 2.6 s through a dns runtime
  as the CA's only DNS.

- **DNS: an authoritative name server runtime.** `socketley create dns <name>
  --zone <file>` serves the zones in RFC 1035 master files over UDP and TCP on one
  port (53 by default), IPv4 and IPv6, in one or `--shards` processes. Records,
  CNAMEs followed within the zone, wildcards, delegations referred with their
  glue, NXDOMAIN and NODATA with the SOA at its negative TTL (RFC 2308), the
  addresses of NS, MX and SRV targets, EDNS with UDP answers kept to 1232 bytes
  and truncated to TCP past it, RFC 7766 pipelining over TCP, ANY answered as RFC
  8482 allows, CHAOS refused. It never recurses and caches nothing, so a name of
  no zone it holds is REFUSED. A zone file is checked whole at `create` (the line
  that is wrong is named) and read again within a second of being edited; a
  broken edit leaves the zone before it. AXFR goes to the addresses `--transfer`
  names, NOTIFY (retried until answered) to the secondaries `--notify` names, and
  `--rrl` (100 a second per /24 or /56 by default) answers past it truncated or
  not at all. On four cores against dnsperf it answered 360-379k queries a second
  on one shard and 473k on two, where NSD 4.8 answered 319-334k and 465-479k on
  the same machine. The packaged service is given `CAP_NET_BIND_SERVICE` so a
  runtime may bind 53. The ids of registered runtime types now begin at 7, the
  sync runtime having taken 6.

- **Storage: bucket CORS, lifecycle, object tagging and reads by part number.**
  PutBucketCors/GetBucketCors/DeleteBucketCors with S3's CORSConfiguration, an
  unauthenticated `OPTIONS` preflight, and the CORS headers on every answer to an
  allowed origin, errors included. PutBucketLifecycleConfiguration and its Get and
  Delete: expiration by days (counted to the next midnight UTC, as S3 does) or by
  date, the abort of incomplete multipart uploads, filters by prefix, tag, size
  and `And`; a paced sweep on each shard deletes through the ordinary delete path
  and counts in `stats` (`lifecycle_expired`, `lifecycle_aborted`);
  `SOCKETLEY_STORAGE_LIFECYCLE_DAY_SECS` shortens a day for tests. Both are
  per-bucket documents written by shard 0, told to every shard before the answer
  and read back at a start. PutObjectTagging/GetObjectTagging/DeleteObjectTagging,
  `x-amz-tagging` on a put, a multipart upload and a copy (`COPY` or `REPLACE`),
  and `x-amz-tagging-count`; a tag change is written in place into one of two
  checksummed slots in the header's padding with one sync, about 2.5 ms whatever
  the object's size, where rewriting a 1 GiB object took 1.07 s. GetObject and
  HeadObject by `partNumber`, from the part sizes a completion now records in the
  object's header.

- **Storage: a slow upload costs a fraction of the CPU, and four shards cost less
  per HEAD and listing.** A body that trickles in (an upload over the internet)
  is read once per 10 ms tick and hashed 64 KiB at a time instead of once per TCP
  segment: 1 MiB through an emulated 50 Mbit, 30 ms link took 28 ms of worker CPU
  before and 9.4 after, paced on loopback 39 and 7; fast uploads are unchanged
  (`stats` counts `body_recvs` and `hash_handoffs`). With four shards a HEAD of
  another shard's key is answered from metadata kept for it instead of opening its
  file (21.9 to 16.2 us of worker CPU per HEAD at 32 connections), and a sibling's
  listing page is written straight from its walk and read without a copy per entry
  (385 to 278 us per listing).

- **A storage runtime against MinIO, and what was made faster.**
  Measured with `warp` and boto3 over plain HTTP with SigV4, on one 16-core VM
  with an ext4 virtio disk, against MinIO single node single drive on the same
  filesystem; median of three alternating passes, the box quiet before each run,
  server CPU (worker plus helper threads, or MinIO) per operation. The table
  gives the median of each cell, with the ratio to MinIO in brackets and the CPU
  in ms per operation for MinIO / one shard / four shards (`--shards 4`).
  MinIO's 64 MiB put at 32 connections wrote more than the disk had room for in
  30 s, so that row is 20 s.

  | cell | MinIO | socketley, 1 shard | socketley, 4 shards | CPU ms/op |
  |---|---|---|---|---|
  | 4KiB GET c1 (ops/s) | 1909 | 8173 (4.28x) | 6090 (3.19x) | 0.55 / 0.03 / 0.04 |
  | 4KiB GET c32 (ops/s) | 18161 | 30576 (1.68x) | 65927 (3.63x) | 0.57 / 0.03 / 0.05 |
  | 4KiB PUT c1 (ops/s) | 54 | 26 (0.49x) | 40 (0.73x) | 1.28 / 0.58 / 0.67 |
  | 4KiB PUT c32 (ops/s) | 533 | 525 (0.98x) | 465 (0.87x) | 1.33 / 0.36 / 0.48 |
  | 4KiB MIXED c1 (ops/s) | 210 | 120 (0.57x) | 114 (0.54x) | 0.81 / 0.17 / 0.20 |
  | 4KiB MIXED c32 (ops/s) | 2916 | 2415 (0.83x) | 2238 (0.77x) | 0.73 / 0.09 / 0.15 |
  | 1MiB GET c1 (MiB/s) | 808 | 1673 (2.07x) | 1638 (2.03x) | 1.53 / 0.16 / 0.17 |
  | 1MiB GET c32 (MiB/s) | 3255 | 13446 (4.13x) | 14106 (4.33x) | 3.25 / 0.14 / 0.21 |
  | 1MiB PUT c1 (MiB/s) | 44 | 26 (0.60x) | 59 (1.35x) | 5.08 / 3.57 / 3.68 |
  | 1MiB PUT c32 (MiB/s) | 169 | 255 (1.51x) | 161 (0.95x) | 7.25 / 4.02 / 5.14 |
  | 1MiB MIXED c1 (MiB/s) | 79 | 53 (0.68x) | 56 (0.71x) | 1.69 / 0.71 / 0.72 |
  | 1MiB MIXED c32 (MiB/s) | 597 | 494 (0.83x) | 490 (0.82x) | 2.33 / 0.66 / 0.79 |
  | 64MiB GET c1 (MiB/s) | 2136 | 2962 (1.39x) | 2972 (1.39x) | 35.67 / 4.35 / 4.36 |
  | 64MiB GET c32 (MiB/s) | 4825 | 18176 (3.77x) | 16969 (3.52x) | 141.10 / 7.69 / 6.42 |
  | 64MiB PUT c1 (MiB/s) | 333 | 419 (1.26x) | 387 (1.16x) | 167.44 / 168.70 / 173.52 |
  | 64MiB PUT c32 (MiB/s) | 556 | 613 (1.10x) | 595 (1.07x) | 535.63 / 267.65 / 441.70 |
  | 64MiB MIXED c1 (MiB/s) | 871 | 1087 (1.25x) | 902 (1.04x) | 43.65 / 28.95 / 27.45 |
  | 64MiB MIXED c32 (MiB/s) | 1373 | 1359 (0.99x) | 1539 (1.12x) | 182.80 / 53.36 / 58.21 |

  Reads are faster than MinIO everywhere (1.4 to 4.3x, at a twentieth of the CPU
  for small objects) and large puts match it. The small-put rows of the table
  are from before a put stopped waiting behind the journal's sync and before a
  put of up to 1 MiB was answered after one sync instead of two (below); with
  both, measured later with warp 1.3.1 and interleaved with MinIO on the same
  disk, a 4 KiB put at one connection is level with MinIO in the disk's fast
  phases (about 120 per second each) and 0.6x in its slow ones (33 against 54),
  and at 32 connections 1.2x or more (540 to 610 against 460); boto3, one
  connection, 4 KiB PUT p50 7.6 to 8.6 ms against MinIO's 8.5 to 17 on the same
  disk minutes apart. MinIO syncs its file once and never its directory, so a
  power cut can take a put it answered; an answered put here survives one. The
  disk's sync latency drifts by two to three times within an hour, so the
  small-put rows move with it. boto3, one connection, 4 KiB, p50 / p99 (table
  era): GET 0.9 / 1.1 ms against MinIO's 1.2 / 1.8, HEAD 0.9 / 1.0 against 1.2 /
  1.8, PUT 41 / 62 ms with one shard and 12 / 23 with four against 27 / 66.

  What changed: the 65536 second-level directories are 256 made with the bucket,
  so a put never makes and syncs one; a put is answered when its file, its rename
  and its directory are durable and the journal record follows behind it (a stop
  syncs it, and any other start reads every object header, which it already did,
  now on one thread per CPU with 32 opens and reads in flight each on an io_uring
  of its own (`SOCKETLEY_STORAGE_RECOVERY_THREADS`, `SOCKETLEY_STORAGE_RECOVERY_DEPTH`),
  all joined before the listener opens: on four CPUs 100,000 objects of 1 KiB
  take 0.24 s with a warm cache (0.8 s one at a time) and about 1 s cold (11 to
  33 s), 1,000,000 take 2.3 s warm (9.8 s) and 19 s cold (344 s), and four
  shards, each reading every header, 0.52 s for 100,000 warm (0.75 s) and 0.94 s
  cold (10 s), 5.4 s for 1,000,000 warm (8.8 s) and 19 s cold (192 s); a start
  after a clean stop reads the journals only, 0.07 s for 100,000 and 0.66 s for
  1,000,000), and that record is synced once a megabyte has gathered, before a
  compaction or at a stop, no longer each time the queue drains, where the next
  put's own sync queued behind it (4 KiB puts at one connection 77 to 104 per
  second); a put of up to 1 MiB with a known length and no condition is written
  into one of 16 empty files each bucket keeps in `pool/`, made and synced ahead
  of time, so that once its file is synced and renamed into place it is on disk
  under one name or the other and is answered then, the syncs of `pool/` and of
  its directory following the answer with the key's next operation waiting for
  them; a start moves any whole file left in `pool/` (length and MD5 as its
  header says) into place (4 KiB puts at 32 connections about 430 to 600 per
  second, boto3 p50 11.3 to 7.6 ms); the MD5 and the SHA-256 that verifies a signed body are taken on helper
  threads (`SOCKETLEY_STORAGE_HASH_THREADS`, by default the machine's cores over
  the shards, at least 1 and at most 3; 0 for the loop), which
  took the loop from 0.86 to 0.37 of a core during 64 MiB puts at 32 connections
  and put a 64 MiB put at 32 connections from 100 to about 400 MiB/s on this
  disk; the signing key of a day is derived once per thread; and an object of up
  to 60000 bytes is kept in memory by every shard that reads it (32 MiB per
  shard, `SOCKETLEY_STORAGE_HOT_BYTES`, 0 for none; `stats` counts `hot_gets` and
  `hot_bytes`), answered by the shard that owns the key only while its version is
  the one the index names, and by any other shard until the owner says the key
  changed: the owner tells every sibling to drop it after a commit or a delete and
  before it answers (`shard_hot_drops_sent` and `shard_hot_drops_served`; a sibling
  that is down is not waited for), and a read a drop arrived during is not kept.
  That took a 4 KiB GET at 32 connections on one shard from 28500 to 45400 per
  second and from 33 to 20 us of worker CPU, and at one connection from 6900 to
  7900; on four shards, where three GETs in four land on a shard that does not own
  the key, from 45 to 30 us of worker CPU summed over the shards at 32 connections
  (about 50 thousand to 56 thousand per second) and from 30 to 20 us at one connection (7100 to
  8100 per second), at about 14 us more for a PUT into memory-backed storage (the
  table above is from before it). A copy of another shard's key keeps its rendered
  response headers too and is found by the same single lookup, so a GET costs a
  shard the same whether or not it owns the key (it was 1.8 us more); four shards
  went from 27.5 to 25.9 us per GET at 32 connections and 32.6 to 30.9 at one,
  against 16.9 at one shard. A connection receives into a buffer a shared
  ring lends it for one completion, with one multishot recv armed across
  requests on a cleartext connection (`SOCKETLEY_STORAGE_RECV_BUFS`, default 64
  of 16 KiB, 0 for a buffer per connection; `SOCKETLEY_RECV_MULTISHOT=0` as for
  the other runtimes), so an idle keep-alive connection holds about 2 KiB instead
  of 10 (10000 of them 20 MiB instead of 100) and a TLS one about 19 KiB instead
  of 92, and a GET costs one submission instead of two; CPU per request and PUT
  throughput are level. The splice
  threshold of 64 KiB was measured and left (below it a read and a write are as
  fast, at 256 KiB splicing is 3.8x).

  A multipart upload whose parts are of one size, as warp, the AWS CLI and boto3
  send anything above 8 to 16 MiB, is written into the object's own file part by
  part and completed by writing the header in front, where the parts used to be
  copied into a new file: the worker writes 64.1 MiB for a 64 MiB object instead
  of 128.0, and on a 4-vCPU VM (EPYC, kernel 7.2) 64 MiB puts at four connections
  went from 3.2 to 6.5 per second (MinIO 6.6) and 256 MiB puts at two from 0.90
  to 1.81 (MinIO 1.79). The storage worker no longer spins on the ring before it
  sleeps, which bought nothing for requests that wait on the disk: on the same VM,
  throughput is unchanged and CPU per request 1 to 22% lower. The same VM against
  MinIO, one shard, three alternating passes, warp on the same four CPUs: 4 KiB
  GET 3.0x at one connection and 3.9x at 32, HEAD 3.9x, 1 MiB GET 2.5x, 64 MiB
  GET 1.8x, listing 3.1x, multi-object delete 2.7x, 4 KiB put 1.7x and 2.5x (about
  900 and 3000 per second), 1 MiB put 1.2x, 64 MiB put level and mixed 1 MiB
  1.6x, with less CPU per request in every row. From a client 31 ms away over the
  internet (k6, 32 connections), 4 KiB GETs and puts run at what the round trip
  allows for both (about 800 to 880 per second), socketley's p99 45 to 47 ms
  against MinIO's 48 to 147.

- **A storage runtime shares what the other runtimes have, and can be scripted.**
  `--tls --cert --key [--ca]` terminate TLS on the listener (sessions are made
  before the first byte is read, so a plaintext client is refused, certificates
  are read at every start so `reload` installs a new one, downloads are encrypted
  rather than spliced, and a peer that never finishes its handshake is dropped
  after thirty seconds). A runtime with a port has the node beside it that a
  server or cache has, and a proxy naming it or its group dials that node.
  `stats` counts answers by S3 code (`error_NoSuchKey`), TLS handshakes and
  failures, and the metrics endpoint carries `socketley_storage_*` series.
  Idle timeouts, `--max-connections`, `--cpus`, state persistence, a proxy in
  front (tcp mode by name and by `@group`, http mode under its prefix) and
  `daemon --fast-lo` are held down by tests. In Lua a storage runtime's script may
  define `on_request(req)`, which runs after authentication and before the
  operation and may refuse (`false`, an S3 error code, or a table with code,
  message and status; a raise refuses too), and `on_put` / `on_delete` after a
  commit; and every runtime's script has `socketley.storage.put/get/head/delete/list`
  to use a storage runtime by name -- waiting in callbacks that can wait (the
  server's connection is kept open for the answer), and with a last-argument
  callback elsewhere, such as a cache's `on_write` or a proxy filter. A script
  moves at most 1 MiB per call.

- **A `storage` runtime: an S3 endpoint over one directory.**
  `socketley create storage media -p 9000 --dir /srv/objects --anonymous -s`
  is a fifth built-in type that unmodified S3 clients (boto3, the AWS CLI,
  rclone) can use with path-style URLs: ListBuckets, CreateBucket, DeleteBucket,
  HeadBucket, PutObject, GetObject (Range and the four `If-*` conditions),
  HeadObject, DeleteObject, DeleteObjects, CopyObject (`x-amz-metadata-directive`,
  within or across buckets) and ListObjectsV2 and V1 (prefix, delimiter,
  continuation token, max-keys, start-after, `encoding-type=url`), with S3's XML
  bodies and error codes, `x-amz-request-id` on every reply, Content-MD5
  checked, and the content headers and `x-amz-meta-*` stored and returned. An
  object is a file with a checksummed header at `<bucket>/data/ab/<sha256 of
  the key>`, and each bucket keeps an append-only journal of puts and deletes
  that is compacted when garbage passes the live objects. A put is written to a
  temporary file, synced, renamed, the directory synced, and only then answered,
  the journal record following behind the answer and synced in a group; a fork-and-`SIGKILL` test over 300 rounds finds
  only whole objects at final paths and nothing acknowledged undone, and a start
  after any crash removes temporary files and rebuilds a lost or damaged journal
  from the object headers. A body is never held whole (a 1 GiB put and get moved
  the worker's peak RSS from 9 to 13 MiB), a GET of 64 KiB or more is spliced
  from the file to the socket and counted as `zero_copy_bytes`, and nothing but
  the startup reconciliation blocks the loop. A runtime needs `--anonymous` or
  credentials (below), `--max-bytes` sets a quota answered with 507, and ACLs
  and versioning answer 501. `type_registry::first_registered` is now 5.

- **A storage runtime authenticates with SigV4, takes multipart uploads and
  checks checksums.** `--access-key K --secret-key S` gives one pair and
  `--credentials FILE` several (`access:secret` per line, re-read within a
  second of the file changing; a file that has gone or no longer parses leaves
  the keys in force); a request with no credentials is 403 unless `--anonymous`
  is also given, and one that carries a signature is always verified. Both the
  Authorization header and presigned GET, HEAD, PUT and DELETE URLs are honoured,
  and every `x-amz-content-sha256` mode boto3 sends is verified as the body
  streams: a hex hash, `UNSIGNED-PAYLOAD`, and aws-chunked with signed chunks,
  with a trailing checksum, or both, also inside `Transfer-Encoding: chunked`.
  The answers are S3's (`SignatureDoesNotMatch`, `InvalidAccessKeyId`,
  `RequestTimeTooSkewed`, `AccessDenied` for an expired URL,
  `XAmzContentSHA256Mismatch`, `BadDigest`); 256 MiB with a hex hash and 256 MiB
  in signed chunks left the worker's peak RSS at 13 MiB. CreateMultipartUpload,
  UploadPart, UploadPartCopy, CompleteMultipartUpload, AbortMultipartUpload,
  ListParts and ListMultipartUploads work with boto3's transfer manager and
  `copy()`: parts are files under `<bucket>/mpu/<id>/` that survive a stop and a
  killed worker, an object is assembled on the ring and committed as a put is
  (six 64 MiB parts, 384 MiB, in 0.33 s with the worker at 13 MiB), its ETag is
  md5 of the part md5s with `-N`, and the parts count against `--max-bytes`.
  Uploads are kept until completed or aborted; `--mpu-expire 24h` aborts old
  ones, at run time and at every start. `x-amz-checksum-crc32`, `-crc32c`,
  `-crc64nvme`, `-sha1` and `-sha256` are checked on PutObject and UploadPart
  (as a header or a trailer), stored, and returned by GET and HEAD with
  `x-amz-checksum-mode: ENABLED`; a multipart object carries the composite
  checksum of its parts.

- **A storage runtime shards: `--shards N` splits it over N workers on one
  directory.** Every shard serves a GET or HEAD by opening the object's own
  file, so no object bytes cross between shards. A key's owner is the CRC16 of
  `bucket/key` mapped to a shard the way a cache maps a slot, so a client can
  compute it; a put streams into a temporary file from the shard that took the
  connection and the owner is sent only its name and metadata to rename it into
  place and append to its own journal (`index.<shard>`), and delete, copy and
  `If-None-Match: *` take the same road, so racing puts of one key never tear
  and every shard serves the winner. Listings fan out and merge into the page
  one shard would give (a shard that cannot answer fails the listing), buckets
  are made and dropped by shard 0 and told to the rest, `--listen unix:` binds a
  node per shard, and `stats` has a section per shard with what crossed. A shard
  killed between a rename and its journal record is repaired from the object
  header when the supervisor restarts it, and a restarted shard removes only its
  own temporary files. A directory started with another `--shards` is rebuilt
  from the object headers rather than refused. `--max-bytes` becomes an equal
  share per shard. A multipart upload lives on the shard that owns its key:
  parts are written where the connection landed and only their names cross,
  CompleteMultipartUpload is validated and sealed by the owner, assembled by the
  shard the request landed on and committed through the owner of the key, and
  ListMultipartUploads merges every shard's; TLS, credentials (and the credentials
  file), scripts and `socketley.storage` calls work on every shard, and the
  metrics series add the shards up. A completed upload now fires `on_put` once
  (its parts do not), and `on_request` names the multipart operations.

- **Cluster runtimes: on a daemon in Raft mode the cluster heals itself.**
  `socketley cluster create server api -p 8080 --replicas 2` declares a
  runtime once for the whole cluster; the leader places each replica on a
  different node (fewest replicas first, lowest id on a tie) and writes the
  assignment to the Raft log, and every node starts, stops and removes its
  replicas through the same `create`, `start`, `stop` and `remove` an operator
  uses. When a node dies its replicas run on survivors with no operator action:
  measured at the defaults on one host with real daemons and `kill -9`, a
  follower's replica was serving again on a survivor after 3.9-4.3 s, a
  leader's after 5.1-6.0 s (an election first). Also `cluster scale <name> <n>`,
  `cluster remove <name>` and `cluster placement`, which shows the runtimes,
  where each is placed and what is unplaced, the leader's view of every node,
  and this node's replicas. A server, a proxy, a client or a cache (below).
  `{node}` in the flags is the name of
  the node running the replica, which is how several nodes share one host
  (`--listen unix:/run/api-{node}.sock`). Replicas are marked `[cluster]` in
  `ls` and `ps` (`"cluster":true` in `--json`, `cluster:replica` in `stats`),
  have no state file, and refuse `stop`, `start`, `remove` and `edit` by name.
  A replica count above the node count runs what fits and `placement` says how
  many are unplaced; nothing is rebalanced when a node returns.
- **A node serves its replicas only while it holds a lease from the leader.**
  A follower asks for one every quarter election timeout; the leader answers
  when it holds a quorum, and calls a node down when it has heard no request for
  `--raft-down-after` (default four election timeouts, at least three). A lease
  runs from when the request was sent and lasts three quarters of that time, so
  a node the leader cannot reach stops serving a quarter of the timeout before
  its replicas move: a minority, an isolated node and a leader that lost its
  quorum stop, and a healed node runs only what the log still gives it. A lease
  that had lapsed is taken up again only after the node has applied the leader's
  log as it stood at the grant. Losing the quorum stops every cluster replica
  on every node until there is one again. A hung daemon (not a dead one) cannot
  stop the workers of a server, a proxy or a client (a cache's fences itself),
  and a leader change longer than the lease restarts the
  survivors' replicas; both are in the manual, with what is not built yet.
  Tested in a simulation of the real Raft core and the real placement logic
  (300 seeds of loss, delay, one-way cuts, splits, kills and reboots in the
  suite, 6000 run once) that checks after every tick that no runtime runs on
  more nodes than it has replicas, and with three real daemons and `kill -9`.
- **A cluster cache survives the loss of its primary's node.**
  `socketley cluster create cache db -p 6379 --replicas 3` gives one primary
  and followers on distinct nodes, replicating with the cache's own
  `--replicate` (a full dump, then every write). When the primary's node dies
  the leader promotes the follower whose copy is the most up to date and writes
  it to the log with the next epoch: measured with `kill -9` and real daemons, a
  survivor took its first write 3.9-4.1 s after a node that was not the Raft
  leader died (11 kills) and 5.2-5.7 s after the leader's (4 kills). A proxy
  with `--backend @db` follows the primary (the cache's name is published as a
  group of one), and `cluster placement` names it, with the epoch and offset of
  every copy. What a replica may do is decided twice: the log must name the very
  process it runs (an incarnation, so a restarted primary comes back empty and
  does not lead) AND its node must hold a lease, and the worker enforces the
  lease itself: it takes the daemon's order every 100 ms, standing for the lease
  the daemon had left, so a daemon that hangs or dies leaves a primary that
  refuses every command within its lease (measured 2.7-3.1 s with a daemon
  stopped by SIGSTOP, 2.8-3.2 s for a primary that lost its quorum, both in nine
  runs). A fence keeps the data, so a primary that lost its quorum for a minute
  is the primary again with everything it held. The old primary that comes back
  follows the new one and takes a full dump. Replication stays asynchronous, and
  the manual says what that loses, measured: with a client writing and `kill -9`
  of the node, none of 4,500-4,900 writes a few seconds apart, none of
  630,000-720,000 pipelined at 230,000 a second, and 876,000-922,000 of about 1.6
  million when both followers had stopped receiving four seconds before; what
  survives is always a prefix of the primary's history. Promotion compares copies
  by epoch and then a count of the records the primary produced, which rides on
  every lease request. A cache with `--tls`, `--listen`, `--shards` or
  `--replicate` is refused as a cluster runtime. Tested in the cluster
  simulation (real Raft core, real brain, the real replica state machine, a
  hung daemon, cuts and reboots; no cache is ever led by two replicas at any
  tick) and with three real daemons.
- **Two nodes cannot share a `--raft-name`.** `{node}` would name both alike, so
  the leader refuses a join whose name (or whose name once made safe for a
  command line) is a member's, and the joiner stops with the reason in its log
  and in `cluster raft-status`.
- **Streams in the cache**, wire-compatible with Redis 7.0: XADD (NOMKSTREAM,
  MAXLEN/MINID with `=` and `~`, LIMIT, `*`, `ms-*` and explicit ids), XLEN,
  XRANGE, XREVRANGE, XREAD with BLOCK, XDEL, XTRIM, XSETID, XGROUP (CREATE with
  MKSTREAM and ENTRIESREAD, SETID, DESTROY, CREATECONSUMER, DELCONSUMER),
  XREADGROUP with BLOCK and NOACK, XACK, XPENDING, XCLAIM, XAUTOCLAIM and XINFO
  (STREAM with FULL, GROUPS, CONSUMERS); `TYPE` answers `stream` and
  `SCAN`/`DBSIZE` take `TYPE stream`. Replies and error texts are compared
  against a redis-server command by command. A stream is kept in blocks of up
  to a hundred packed entries, cut where Redis cuts its nodes so `MAXLEN ~`
  trims what it trims there; a million short entries hold 24 bytes each
  against Redis's 25. Readers blocked on a stream are woken by the XADD they
  wait for. The dump, the journal and a follower carry entries, counters,
  groups, consumers and every pending entry with its delivery time and count;
  an XADD with `*` replicates the id it got. XADD, XGROUP CREATE and
  CREATECONSUMER are refused at `--maxmemory`, as Redis refuses its denyoom
  commands. On a sharded cache XREAD's streams must belong to one shard, and a
  blocking read is served by the shard that owns them (its `--cluster` port).
  Against Redis 7.0.15 over four `redis-benchmark` clients: XADD 1.23× at
  depth 1 and 2.59× at depth 16, XRANGE and XREAD about 1.85× and 3.2–3.5×,
  XREADGROUP 1.87× and 3.87×, XACK level.
- **SDK:** `cache_store` holds streams (`stream_get`, `stream_find`,
  `stream_make`, `stream_admit`, `stream_change`) as `stream_log`, which is
  usable on its own from `socketley/runtime/cache/stream_log.h`.
- **`socketley daemon --fast-lo [own|all|trust]`** puts TCP pairs whose both
  ends are on loopback (127.0.0.1, 127.0.0.1 IPv4-mapped on a dual-stack
  socket, or ::1) on a kernel shortcut: a BPF sockops program enters both
  sockets in a sockhash when the connection is established, and an `sk_msg`
  program places every send straight into the peer's receive queue, skipping
  TCP/IP, the loopback device and its softirq. Off unless given; the mode
  defaults to `all`. Needs `CAP_BPF` and `CAP_NET_ADMIN` and cgroup v2; without
  them the daemon logs `fast-lo: unavailable, serving without it` and serves
  on the ordinary path. The programs are hand-assembled, loaded with a raw
  `bpf(2)` (a verifier `EAGAIN` from the daemon's own pending io_uring task
  work is retried, as libbpf does) and detached when the daemon exits.
  - **Modes.** `own`: only pairs whose both ends are the daemon's runtimes,
    such as a client runtime and a server runtime. `all`: also a local client
    of any process connecting to a runtime's port, and every connection a
    runtime makes to any local listener (a tcp proxy with `--backend
    127.0.0.1:8080` in front of a local application, a client runtime, a Lua
    HTTP call). `trust`: `all` without the receiver rule below.
  - **The receiver rule (`own`, `all`).** A send is redirected only when the
    socket that will receive it is one of the daemon's workers' (a runtime that
    connected, or one that accepted on a runtime's listener); a send into a
    foreign socket goes by ordinary TCP, each direction of a pair decided by
    its own receiver. A redirected byte sits in the receiver's ingress queue,
    which only `recvmsg` drains: a foreign process reading with `splice(2)`,
    `sendfile(2)`, `TCP_ZEROCOPY_RECEIVE`, Go's `io.Copy` between two TCP
    connections or HAProxy with splicing never sees it (measured: a Python
    backend splicing behind a proxy echoed 0 of 500 bytes) and cannot be told
    apart from outside. The rule keeps such readers whole; the price is that a
    foreign client of a cache, or a proxy's foreign backend, gains nothing on
    the reply. `trust` is for an operator who knows every local client reads
    with `recv`/`read`/`recvmsg`: it redirects into foreign receivers too and
    a reader that splices loses its bytes. `daemon stats` and
    `socketley_fast_lo_info{mode}` say which is running. Our own proxy already
    keeps splice off any pair with a loopback leg. Measured with
    `redis-benchmark` (50 connections, 4 threads) against a cache, six
    alternating passes, requests per second off / `all` / `trust`: GET -P1
    240-279K / 222-250K / 387-667K, SET -P1 222-286K / 197-273K / 462-632K,
    GET -P16 2.3-4.0M / 2.7-3.4M / 5.3-6.9M; a bulk reader of 64 KiB values
    1377-1488 / 1276-1322 / 2464-3040 MB/s (one GET -P1 pass of the first run,
    169K off, was taken beside another job and is left out). A client runtime
    against a cache, both ends ours, round trips per second off / `all`: one
    in flight 83-85K / 110-116K, eight 577-700K / 686-771K; a tcp proxy to a
    local C echo backend, 64 B one connection, 44-48K off / 41-45K `all` /
    86-88K `trust` (the last measured on the build before the receiver rule,
    which redirected exactly as `trust` does).
  - **Bounded.** The redirected backlog is capped by `--fast-lo-limit
    <per-pair-MiB>,<global-MiB>` (default 4,64): the `sk_msg` program counts
    each pair's sends in a BPF map and, each time the count passes a mark, asks
    a reconciler thread through a BPF ring buffer for the peer's true queue,
    which it reads with one exact `sock_diag` lookup (`INET_DIAG_SKMEMINFO`,
    which counts the ingress backlog on this kernel) and hands back in tens of
    microseconds. A reader that keeps up is snapped back, so a pair moving 3
    GB/s stays on the shortcut; a pair whose peer really holds the per-pair
    bound, or whose count reaches twice it unanswered, is tainted to TCP, which
    then gives the ordinary `EAGAIN` backpressure, and a flag taints new sends
    once the sum across pairs reaches the global budget. A sweep once a second
    recomputes the sum and re-asks any check whose answer was lost. Without a
    bound a receiver that read nothing took 731 MiB before the kernel's global
    TCP memory ran out; with the default it stays near 4 MiB per pair. The
    taint is permanent, which keeps bytes in order: `tcp_bpf_recvmsg` drains
    the redirect queue before the TCP receive queue. Two edges stay coarse: a
    pair moving gigabytes a second whose answer is held up for more than about a
    millisecond reaches the hard ceiling and is tainted (costs speed, not
    bytes), and many pairs stalling in the same instant can each hold their
    per-pair bound before the global flag is raised.
  - **Fenced.** Under `all` and `trust` the sockops program is attached at the
    root cgroup, where it fires for containers too, so it bakes in the
    daemon's netns cookie (`SO_NETNS_COOKIE`; without it the shortcut refuses
    to attach) and takes only sockets of that namespace, and every insert at
    entry is `BPF_NOEXIST`, so a container's identical 127.0.0.1 tuple can
    neither overwrite a daemon socket's entry nor be redirected into. A
    connect of ours that never establishes deletes its mark on close.
  - **Seen.** Shortcut bytes skip netfilter, conntrack and the loopback
    device, so nftables on `lo` and `tcpdump -i lo` do not see them.
    `socketley daemon stats` prints `key:value` lines and the metrics endpoint
    carries `socketley_fast_lo_*`: the mode (`off`, `own`, `all`, `trust` or
    `unavailable` with the reason), sockets on the shortcut and pinned to TCP,
    sockets entered, taints by reason (`bound`, `unanswered`, `budget`,
    `peer_off`), and bytes held against the budget, counted in a per-CPU BPF
    array with one atomic add per entered socket and per taint, never per send.

- **`socketley daemon --raft-listen <ip:port>` runs a Raft node on the daemon.**
  Off unless asked for; nothing else about the daemon changes, and the cluster
  directory keeps working as before. It forms the cluster and keeps it: leader
  election with pre-vote and check-quorum, a replicated log on disk,
  membership, and graceful handover. Cluster runtimes and cluster caches
  (below) are what goes through its log.
- `--raft-init` founds a cluster; `--raft-join <ip:port>` joins one, first as a
  learner and then promoted to voter once caught up. Both apply to the first
  start only; afterwards the node comes back from its own state.
- Mutual TLS between members is required (`--raft-cert`, `--raft-key`,
  `--raft-ca`, `--raft-name`); a certificate that does not name the member it
  speaks for is refused. `--raft-insecure` runs it in cleartext on purpose.
- The log is a CRC32C-checked WAL under the state directory, 0600, every write
  fsynced through io_uring before anything that depends on it is sent; a torn
  tail is cut back on restart. A SIGTERM'd leader hands leadership over first.
- `socketley cluster raft-status` shows role, term, leader, commit/applied,
  voters, learners and whether a quorum is reachable, and exits 2 without one.
- **The whole cross-runtime Lua API works in a worker.** Thirteen calls were
  refused there; the count is zero. `socketley.send/.list/.get` and
  `socketley.cluster.*` are answered from a replica map the daemon pushes;
  `.create/.start/.stop/.remove` are asked of the daemon over a socket of the
  worker's own and wait for the answer, so `if socketley.create(...) then`
  branches on what happened; and `socketley.pipe` across two runtimes and
  `self.route()` reach a runtime in another process. Despite the name neither
  hands a descriptor over — the origin keeps the socket and relays.
### Fixed

- **JMAP's preview ended in a space** where the message's text ended in
  white space.
- **JMAP had no conversations.** Every Email was a Thread of its own and
  collapseThreads was ignored. A message's conversation is now the hash of the
  Message-ID its References begin with (else In-Reply-To, else its own), taken
  at delivery and APPEND, kept in the IMAP index on every shard, and read for
  older messages the first time a client asks; Thread/get gives every Email of
  one across mailboxes, oldest first, and Email/query collapses by it.
- **JMAP's Email/set lost what a webmail writes into a draft.** A Bcc was not
  kept, so sending the draft without an envelope never reached it; a draft
  with no recipient yet, or with a Message-ID of its own, was refused; the
  recipients' names were dropped; and a move written as RFC 8621's example
  writes it, the old mailbox's null before the new one's true, was refused,
  its keywords changed all the same. A quoted display name read from a message
  kept its backslashes, which a reply then doubled.

- **`import name '{"key": value}'` was "invalid JSON", or applied nothing.** A
  document without `name` was refused, and one without `type` had every field of
  the runtime's own type left unread, so `{"name":"px","circuit_timeout":18}`
  reported success and changed nothing. A document that leaves them out is now
  about the runtime the command names, with its type.

- **Storage behind a proxy counted every client as the proxy.** Failed sign-ins,
  `aws:SourceIp` and the access log read the socket's peer, so behind Apache or
  the entrance one guesser locked everybody out of the web interface and an IP
  condition could not tell clients apart. A connection from a proxy
  `--tls-offloaded` names now takes the client from the last address that proxy
  put in `X-Forwarded-For`, per request.

- **TLS listeners offered CBC and SHA-1 suites over TLS 1.2 and resumed from
  tickets.** A listener now offers Mozilla's intermediate list (ECDHE with AEAD
  only) and resumes from its session cache, so a ticket key that lives as long
  as the process cannot open the sessions it sealed.

- **`stop` then `start` of a server, cache or storage runtime could leave it with
  no node beside its port.** The stopped worker's destructor unlinked the node
  path when the process exited, tens of milliseconds after the stop, which could
  be after the next worker had bound it.

- **An idle `mqtt` runtime with `--persistent` wrote its snapshot every ten
  seconds.** Each `$SYS/broker/` figure it publishes counted as a change, so the
  snapshot was rewritten and synced for an uptime, and a start read the last
  process's figures back. They are now neither a change nor in the snapshot,
  and `stats` says with `snapshot_unsaved` whether a change is not in one yet.

### Changed

- **Cache: `allkeys-random` at its limit takes a victim by sampling the table**,
  as Redis does, instead of walking the LRU list to a random index. A write
  over the limit cost half the keyspace in pointer chasing: 200-byte SETs into
  a 16 MiB cache went from 4,375 to 566,000 a second and from 228 to 1.75 us of
  CPU each (three alternating passes). The policy is unchanged; the walk is
  kept for a table emptied far below its bucket count.

- **Cache: a client blocked with no timeout no longer wakes its worker.** The
  blocked-pop tick ran ten times a second while anyone was parked; it now runs
  only while a waiter has a deadline or reads a group whose stream can go. One
  `BLPOP key 0` parked: 139 wakeups in ten seconds before, 0 after.

- **Shard crossings are framed once and read without copies.** A request or an
  answer between two shards was built three times on the way out, its frames
  were erased one at a time from the front of the read buffer, and each was
  decoded into owned strings; the send queue was copied into the wire buffer
  every batch and is swapped now. GETs on a four-shard cache: 2.3% less CPU
  each (median of eight paired passes).

- **Storage: a file body over HTTPS/1.1 reaches the record layer without two
  copies of every 256 KiB piece.** 4 MiB GETs over TLS: 14% less CPU each and
  16% more a second (median of five paired passes). A sealed or compressed
  window is no longer zeroed before it is read into, and a sharded listing
  merges the shards' sorted pages instead of sorting all of them.

- **HTTP/2: HPACK Huffman strings decode eight bits a step instead of one,**
  1.8-5x faster per byte, checked against the bit-at-a-time definition on
  random input.

- Smaller ones: EVAL writes its reply where it is sent and finds a script at
  the front of its cache without hashing it (3% less CPU); the journal's
  CRC-32 folds eight bytes a step; LREM walks a packed list once; a pattern
  message is built once per pattern rather than once per subscriber; a
  websocket broadcast frame is built inside the segment it is sent from; a
  `socketley.pipe` line, `-b` output and `-w` lines allocate nothing per
  message; the proxy asks a unix peer's address once per connection; TLS
  flushes in the server, cache and client reserve their records as the proxy
  does; an outbound storage peer resumes its TLS session; the dashboard reads
  proportional memory once per sample, not once per poll; a DNS runtime's
  512 KiB of datagram buffers are no longer zeroed, so an idle one keeps them
  off its resident set.

- **Storage: a copy of a multipart object is a single-part object**, as S3
  makes it: its ETag is the MD5 of its bytes without `-N`, taken during the copy,
  and `partNumber=1` reads all of it. Copies used to keep the source's multipart
  ETag.

- **Unix stream sockets get a 1 MiB send buffer** (512 KiB asked, doubled by
  the kernel, capped at `net.core.wmem_max`): every socket accepted off
  `--listen unix:` or a companion node by a server, cache or proxy, a proxy's
  connection to a `--backend unix:` or a local runtime's node, and a client's
  `-t unix:`. The sender's buffer is all the flow control a unix stream has,
  and an accepted one inherits nothing from its listener, so these ran at the
  208 KB default. One connection of pipelined 64 KB GETs, both builds up at
  once and alternating: a Python reader taking 4 MiB a read 2.21–2.33 →
  2.88–3.09 GB/s (1.32×, per-pass 1.27–1.38, n=11) with the cache worker at
  0.57 → 0.44 cores, 41% less CPU per byte; a TCP proxy in front of a cache
  reached over its node 3.21–3.82 → 3.53–4.26 GB/s (1.10×, 1.00–1.27, n=11);
  a proxy on `--listen unix:` 1.10× (0.86–1.38). A C reader and a Python
  reader taking 64 KB a read were at ~10 GB/s with the worker's core as the
  ceiling, and stay there (1.02×, 1.05×). `redis-benchmark -c 50 --threads 4`
  GET and SET at `-P 1` and `-P 16`: 0.96–1.00× per-pass medians, inside one
  tick of its ~0.125 s completion check. 512 KiB is the knee: 256 KiB gave less than
  half the gain and 1–4 MiB none more. Memory: 1000 idle connections
  hold 0 bytes of send buffer either way and the worker's RSS is unchanged; a
  connection whose reader stopped holds 1.07 MB in the kernel instead of
  223 KB. The server's per-accept 128 KB `SO_RCVBUF` on unix clients is gone:
  a unix stream receiver's buffer does not limit anything (4 KB and 4 MB read
  the same).
- XACK finds a pending entry through a hash index instead of walking an
  ordered tree of every pending entry: 50% more XACKs on a group with
  200,000 pending (level with Redis before, 1.48× after), at about 20 bytes
  more per pending entry.
- **A cache serves only this machine unless told otherwise.** A TCP peer whose
  address is not loopback is answered `-DENIED` and closed. A cache has no
  password and answers every client with everything it holds, so reaching one
  from the network is now something to say: create it with `--public`, or give
  its listener mutual TLS (`--tls --ca`). A follower on another host needs its
  leader to be public. Unix-socket peers are unaffected.
- A relative path in a flag the daemon opens (`--lua`, `--log`, `-w`,
  `--persistent`, `--http`, the TLS files, `--listen unix:`) is resolved against
  the directory the command was typed in, not the daemon's.
- A proxied HTTP request carries `X-Forwarded-For`, `-Proto` and `-Host`.
- The daemon ignores SIGHUP; rotate `--log` and `-w` files with `copytruncate`.
- The packaged unit reads home directories (`ProtectHome=read-only`), so a
  script or certificate kept there can be used.
- **SDK:** `cache_store::hget()` and `lindex()` return
  `std::optional<std::string_view>` instead of `const std::string*`, and the
  list `list_ptr()` returns is read through `at()` and iterators of views. A
  small hash and a small list are packed and hold no `std::string` to point at.
- A cache is faster once its keyspace outgrows the CPU caches: the keyspace is
  an open-addressed table, the RESP loop fetches the keys of the next eight
  pipelined commands ahead of running them, and MGET/MSET fetch theirs in
  batches. Pipelined GET over 100,000 random keys went from 4.7 M to 8.8 M/s,
  over a million from 2.9 M to 7.4 M; MGET and MSET of ten keys gained 72–78%.
- Small hashes, sorted sets and lists take less memory: a five-field hash 631 →
  248 bytes, a five-member sorted set 1,575 → 248, a five-element list 808 →
  231. RPUSH is a third faster and LRANGE 9–12%; LINDEX and LSET on lists of
  tens of elements are up to 14% slower, since a packed list is walked.
- A cache key costs 17 bytes less in every type, and a small set 81 bytes
  less: the keyspace and field tables hold one word per slot instead of two.
  Writes into one large hash are 6% faster.
- A cache key's entry holds its key as a 4-byte length instead of a 16-byte
  view, 16 bytes less a string, hash or list key: a string key is 85 bytes
  against Redis's 104, a five-field hash 165 against 168.
- A small sorted set stores a whole-number score in 1, 2 or 4 bytes instead of
  8, as Redis's listpack does, and no longer carries the index pointer only a
  large one uses: 133 bytes a five-member set against Redis's 136.
- ZREVRANGE on a small sorted set is 67% faster and ZINCRBY 58% faster.
- A large sorted set keeps each member's name once, inside its skiplist node,
  and finds a member through an index of the nodes themselves: 90 bytes a
  member of a million-member set instead of 186 (Redis 125), ZADD into it 21%
  faster and ZRANK 12% faster.
- ZINCRBY or ZADD that leaves a member between the same neighbours changes
  its score in place instead of taking it out and putting it back: 5% more
  ZINCRBYs by 0.001 on a million-member set, at 6% less CPU each.
- ZADD is about twice as fast (0.53× Redis → 0.99×), SADD into a large set 54%
  faster, and HGET/ZSCORE over many small keys 30–50% faster.
- The proxy sends a relayed message directly when nothing is queued ahead of
  it, instead of through a submission and a completion: one connection's small
  round trips went from level with nginx's stream proxy (0.96-0.99x) to
  1.03-1.08x, at 11% less CPU per round trip.
- A server's and a cache's answer to a single client goes out by a direct
  send instead of a submission and a completion: 2.5-3% more round trips and
  6-7% less CPU each. With several clients the answers still share one ring
  entry per turn, which a send per answer measured slower.
- A server's message to its upstream goes out by a direct send when nothing
  is queued ahead of it, as its answers to a single client already did, and
  `self.upstream_send` no longer builds a string and a shared pointer per
  message: 2.2% more upstream round trips, the distance to a C relay 2.39 →
  1.82 µs.
- A line a server script sends to one client with `self.send` goes out
  straight from the script's string when nothing is queued ahead of it,
  instead of being copied into a new string first: 2.7% more 16 KB round
  trips through a Lua echo, the distance to a C echo 2.04 → 1.65 µs.
- A message a server script sends to one WebSocket client with `self.send` is
  framed without being copied twice: when nothing is queued ahead of it the
  frame goes out from a header on the stack and the script's string, and
  otherwise it is built once from the message. 1.5–3.3% more WebSocket round
  trips through a Lua echo; the distance to a C echo 1.44 → 1.16 µs at 64
  bytes and 1.80 → 1.48 µs at 1 KB.
- A client hands its script each line straight from the buffer it was read
  into, and copies only a line still unfinished at the end of a read: the
  distance to a C client at 16 KB lines 1.49 → 1.28 µs; unchanged at 64 bytes
  and 1 KB.
- Server, proxy, cache and client count their messages, connections and bytes
  with plain adds instead of locked ones, since only their own loop writes
  them. No difference this machine resolves.
- A read re-armed on a socket the last read left empty waits for data instead
  of first trying a receive that can only come back empty: the proxy's HTTP
  and early TCP reads, its read on a backend taken from the pool, a server's
  upstream read, and a client's single-shot read. No difference this machine
  resolves yet.
- A server's HTTP path allocates less per request: the header list is kept
  between requests on a keep-alive connection, a GET's `Cookie`, `Origin`,
  `Sec-WebSocket-Protocol` and `Authorization` are copied only for a WebSocket
  upgrade, a static path without a percent escape is looked up without being
  copied, a response with nothing queued ahead of it goes straight to the
  socket, and `on_http_request` gets its tables built at their final size and
  its `body` copied once. Together: the distance to a C server on one
  keep-alive connection 1.48 → 1.36 µs.
- `EVAL` is 46% faster, and a script calling `redis.call` about twice as fast:
  `redis.call` works on the Lua stack and hands its arguments to the cache
  without encoding them as RESP. An error a script catches from `redis.call`
  is the cache's own text, without a `lua: error:` prefix.
- A proxied HTTP request is rewritten into a buffer its connection keeps, so
  a keep-alive connection no longer allocates and frees one per request.
- An HTTP proxy with one backend keeps a keep-alive client's backend
  connection for that client's next request, from its second answer on,
  instead of returning it to the pool and probing it on the way back out, as
  HAProxy's `http-reuse safe` does. A backend closing such an idle connection
  costs the client nothing and is not counted against the backend's circuit
  breaker, and an idempotent request that meets that close on its way out is
  sent again on a fresh connection instead of answered 502. A held connection
  idle past the pool's 60 s is not reused; `stats` shows the held connections
  as `parked_connections`, and they go to the pool when the client leaves.
  Against HAProxy on one keep-alive connection 1.30× → 1.32× the rate and
  1.51× → 1.62× per core; at 32 connections 1.32× → 1.47×.
- **A script runs when its runtime starts, not when it is created.** `create`
  compiles the file — one that does not parse is still refused by the command
  that asked — and the worker runs it. Without `-s` there is no worker yet, so
  the top level has not run, `socketley.subscribe` has not registered, and a
  global like `tick_ms` has not been checked; all of that happens at `start`,
  and a refusal there is reported by that command. Previously a runtime kept in
  the daemon loaded and ran its script during `create`.

### Fixed

- Two CalDAV or CardDAV clients editing one entry under the same `If-Match`
  could both be taken, the second overwriting the first; the condition is now
  asked of the storage under the entry's own lane, so one is taken and the
  other answered 412. A DELETE under `If-Match` is the same.
- A Lua handler that waited twice on `self.cache` could take the late answer
  to its first, given-up wait as the answer to its second.
- A follower that missed an election took the new leader's answer to its
  read index as coming from nobody, and the read never completed.
- A stop in the moment a delivery outbox was being started again empty could
  lose the records queued in that moment.
- SINTERSTORE, SUNIONSTORE and SDIFFSTORE are refused with `-OOM` when their
  result has no room under `--maxmemory`, and leave the destination as it
  was; they stored it past the limit.
- LPUSH, RPUSH, SADD, ZADD, ZINCRBY and LSET past `--maxmemory` answer `-OOM`
  instead of `WRONGTYPE` (LSET: `index out of range`), and LMOVE instead of
  nil, so a client no longer treats a full store as a key of another type.
  LSET on a key of another type answers `WRONGTYPE`, as Redis does, not
  `no such key`.
- COPY past `--maxmemory` answers `-OOM`, as Redis does, instead of `0`, which
  a client reads as "the destination exists"; the text protocol answers
  `error: out of memory`.
- Under a memory limit with an eviction policy, `LMOVE` and `RPOPLPUSH` could
  evict their own source list to make room in the destination, answering nil
  with the element in neither list; `SMOVE` could likewise evict the rest of
  its source set. The source is now never an eviction candidate for its own
  move: another key is evicted, or the move is refused with nothing lost.
- A server now fails a WebSocket connection whose text message is not valid
  UTF-8, with close code 1007, as RFC 6455 8.1 requires. Such a message used
  to be handed to `on_message` and `on_client_message` as it was, and with no
  script relayed as a binary frame. A message split into fragments is judged
  whole, so a character split across two fragments is accepted. Binary
  messages are not checked.
- A binary WebSocket message whose bytes happened to be valid UTF-8 was
  relayed by a server without a script as a text frame, so a browser got a
  string where it expected a Blob or ArrayBuffer. A relayed message now keeps
  the opcode it arrived with, including after reassembly from fragments and
  when it was held for a client still finishing its upgrade. What a script
  sends is framed as before: text if it is valid UTF-8, binary otherwise.
- A backend that answers `HTTP/1.0` without `Connection: keep-alive` closes its
  connection behind the answer, and the proxy no longer keeps that connection
  for the client's next request: the request goes out on a new one instead of
  into the one closing, where it was sent twice or answered 502. The client's
  own connection stays open.
- An HTTP client that closes its side while its answer is still coming -- one
  that ends only when the backend closes, or one short of its Content-Length --
  is no longer held open for as long as the backend stays silent: from then on
  the backend may go `--backend-timeout` without sending before both
  connections are closed. A half-closed client still receives an answer that
  keeps coming.
- A backend that answers a HEAD with a body, or otherwise sends bytes after
  an answer, no longer has them glued to the next answer on the same backend
  connection: the proxy sends that request again on a fresh connection, or
  answers 502, instead of relaying bytes that do not start a response. The
  client connection is also no longer left open behind that answer after
  the client closes it.
- A WebSocket upgrade on a keep-alive connection that had already served a
  plain GET could hand `on_websocket` and `self.ws_headers` that GET's
  `Cookie`, `Origin`, `Sec-WebSocket-Protocol` or `Authorization` when the
  upgrade itself did not carry the field.
- A script that stopped its own runtime from inside a callback
  (`socketley.stop(self.name)` in `on_message`) read and popped an empty frame
  stack once the callback returned.
- A TCP proxy whose backend shut its sending side first no longer drops the
  rest of what the client is still sending: the backend's FIN reaches the
  client after the last byte of its answer, and the pair closes once both sides
  have finished, as HAProxy does.
- The proxy finds the end of a chunked response, so the next keep-alive request
  is served at once instead of after the 10 s header deadline, and the end of a
  chunked request body, so a request pipelined behind one is checked like any
  other instead of reaching the backend raw.
- A follower can join a leader holding more than 8 MiB.
- A dump restores a TTL as the deadline it was, not as the time that was left.
- A write accepted after a torn journal tail survives the next crash.
- `EVAL` refuses precompiled bytecode.
- A script can no longer end the cache's worker: a returned table whose
  `__index` raised did, and so did `EVAL` from inside `EVAL`. A script is
  refused, as Redis refuses it, the commands that would outlive it on the
  caller's connection (`MULTI`, `WATCH`, `SUBSCRIBE`, `EVAL`, `SCRIPT`, `RESET`,
  …), and a blocking pop in a script answers at once.
- Twelve cache answers Redis clients depend on, among them a bare
  `UNSUBSCRIBE`, the subscription count, `HSET`'s count, `READONLY`, and
  `FLUSHALL` and `MULTI` on a sharded cache.
- A stopping persistent cache is given time to finish its dump.
- A request the server or the proxy refuses while it is still arriving (413,
  431, 400, 502–504) reaches the client instead of being reset away by the
  unread rest: the connection reads it away behind its FIN, for up to ten
  seconds or 64 MiB.
- A server answers a request head past 16 KiB with `431`, as documented,
  instead of closing without a word.
- A worker whose control socket backs up says so once per stall, not once per
  refused frame.
- A cache's memory limit holds against a hash field or list element set long
  and then short: the long value's buffer stayed behind, charged as the short
  one, so 64 fields set to 100 KB and back to one byte held 6.4 MB the cache
  counted as 5 KB, as many times over as a client liked.
- A cache's memory limit counts what a collection holds besides its elements:
  a list's segment blocks and map, a hash's table and slots, a sorted set's
  skiplist head and index, a set's slots, and the room a small one's buffer
  keeps after it shrinks. Lists of one 100-byte element filled a 1 MB limit
  with 2.6 MB, and a hash, set or sorted set grown to 100,000 members and
  emptied to one held 2 MB counted as nothing. A large hash, set or sorted set
  now reads about 9 bytes a member more, a list key 24 and a set key 48.
- The name of a sorted set created by `ZADD` and of a list created by `LMOVE`
  is counted; it was given back when the collection emptied, so each such
  round trip wore the count down by the length of the name.
- `COPY`, `RENAME`, the `STORE` forms of set algebra, `SMOVE` and an `LTRIM`
  to nothing keep a cache's memory count: a copy or a stored set was never
  counted and was taken off when deleted, a rename kept the old name's size,
  `SMOVE` never gave back what it moved, and `LTRIM` gave back every element
  twice. Each wore the count toward zero, and the limit with it, and deleting
  a copied list or set left the count at 16 EiB. `COPY` past the limit copies
  nothing and answers 0, counting what `REPLACE` frees, a renamed key can be
  evicted again, and `SMOVE` onto its own set leaves the member where it is.
- A worker that will not accept its configuration now sends the reason up, so
  `create` says `'path' must start with '/'` rather than "the reason is in the
  daemon log".
- `on_cluster_join`, `on_cluster_leave` and `on_group_change` reach a worker.
  They previously fired only for a runtime inside the daemon, which since the
  split meant nowhere.
- A map change made from a script is visible to that script immediately:
  `socketley.stop("x")` followed by `socketley.get("x")` reports `stopped`,
  where the worker's replica used to answer `running` until the next push.
- When a runtime holding routed connections goes away — stopped, removed,
  crashed or killed — every runtime on the other end is told to let go, and its
  `on_disconnect` runs. The daemon does the telling, because a killed worker
  runs no teardown of its own.

### Removed

- **Every runtime now runs in its own supervised worker process.** One runtime
  can no longer take the daemon down with it. There is no opt-out and no flag:
  `--daemon-process`, and the older `--out-of-process` / `--in-daemon` pair it
  replaced, are all gone. A command line carrying one is refused as an unknown
  flag; a configuration file with `daemon_process` in it is refused naming the
  line.

## [1.1.0] - 2026-08-27

Six months of work since v1.0.9, across 581 commits. The headline is that a
runtime is no longer confined to the daemon's process or to one core.

### Added

#### Multi-process runtimes and sharding

- **Every runtime now runs in its own supervised worker process by default.**
  One runtime can no longer take the daemon down with it. `--daemon-process`
  opts back in to sharing the daemon's process; it replaces the older
  `--out-of-process` and `--in-daemon` pair, which were one bit under two
  spellings.
- **`--shards N`** runs a single runtime across N worker processes behind one
  port via `SO_REUSEPORT`, on servers, proxies and caches.
- A **sharded cache keeps one keyspace.** `mget`, `dbsize`, `publish` and
  `SET`/`GET` answer for the whole runtime rather than for whichever process
  the client happened to reach. Dumps record their shard count and refuse to
  load under a different one, because that loses keys in silence.
- A **sharded server's Lua** sees the runtime, not its own process:
  `self.clients()`, `self.send` and the connection counts span all shards.
- A **cross-process request channel**, so a runtime in one process can ask a
  runtime in another — and a runtime that cannot see its target now says so
  instead of answering as though the target did not exist.
- **`socketley.cluster.*` and the runtime map work inside a worker.** Twelve
  Lua calls that used to be refused for being in a worker now answer.

#### TLS on every role

- **Server**, **cache** and **proxy** listeners terminate TLS, including mutual
  TLS via `--ca`.
- **Client** runtimes dial over TLS, pinning the host from `-t` and verifying
  the chain against the system store.
- A **proxy dials its backends over TLS on the other leg**, and reuses the
  backend handshake instead of performing one per request.
- The **health probe handshakes**, so a TLS backend can be checked by asking it
  something rather than by opening a socket at it.
- A cache **refuses to replicate out of a TLS listener in cleartext**.
- The **SDK can present a client certificate**.
- `--tls` with `--udp` is refused: that would be DTLS, which is not implemented.

#### Clustering, transport and routing

- **`--cluster`**, off by default — client routing is a decision rather than a
  consequence of `--shards`.
- **`--listen unix:/path`** on a listener and **`--backend unix:/path`** for a
  proxy's backends.
- **`--cpus max | 0-3 | 0,1,2,3`** says where the I/O may run, and **SQPOLL is
  now a choice** rather than always on.
- A **WebSocket client can talk through a socketley proxy** instead of hanging
  after the handshake.
- A filter can **remove** a header, not only add or overwrite one.
- An endpoint can declare **which methods it takes**, so the gateway can refuse
  the rest.
- A connection can be **moved to another process, or relayed to one**.
- `socketley daemon` reads the command line it is given.

#### Lua

- **A callback that never returns no longer takes the daemon with it** — there
  is a deadline.
- `socketley.unsubscribe`, so a subscription can be ended.
- A runtime in a worker declares its routes and the daemon publishes them.

#### Operations

- `socketley stats` reports a worker's figures with an age, rather than as
  though it had just read them.
- A runtime that **failed to start is visible to `ps`** — which is the command
  an operator types when a runtime did not start.
- `create` no longer stalls every other runtime for the duration of its
  `fsync`.

### Security

- **The IPC socket is `0660 socketley:socketley`.** It was `0666`, so any local
  user could drive the daemon and run code as its owner. Membership of the
  `socketley` group is now the administrative boundary; upgrading tightens it,
  and the package says so on install.
- **A cache's `--persistent` dump is no longer readable by every user on the
  machine.** The state directory is `0750` and the records inside it `0600`;
  they contain `--master-pw` in plaintext and the paths of TLS private keys.
- **A `.deb` now ships `/usr/share/doc/socketley/copyright`.** It previously
  shipped none, which was both a Debian policy break and a distribution of
  statically linked MIT code with no notice attached.

### Fixed

264 fixes. The ones a user would notice:

- A **runtime whose worker refused its configuration was recorded as running**
  and restored on the next daemon start, where it stole unix socket paths and
  answered 404 forever.
- **HTTP request framing** was stated nine times across two runtimes, and seven
  of its eight rules existed in only one of them — the server executed smuggled
  requests the proxy refused. It is now one decision in
  `shared/http/http_framing.h`.
- A **connection left waiting on a read only its dead peer could finish** — the
  same defect in the cache and, months later, in the server. Now decided once
  in `shared/net/conn_reachability.h`.
- **HTTP took one request per read** and left the rest for a read that was
  never coming.
- `reload-lua` on a script that would not compile left the runtime **with no
  script at all**; on a script with a timer it freed the context and left the
  timer pointing at it.
- A **stopped runtime went on running its script's timers**.
- Cancelling a Lua timer **muted it without withdrawing it**.
- `start` reported success for a worker that had not started, and `reload`
  never reached one.
- A full submission queue was read as a permanent failure and **the message was
  thrown away**.
- A RESP client in the relay set **read relay bytes as its reply**.
- One client that stopped reading **held a stopped runtime forever**.
- A **configuration file could not ask for a runtime in the daemon**.

### Changed

- The `--out-of-process` / `--in-daemon` flag pair is replaced by
  `--daemon-process`. Neither old spelling is kept as a synonym.

---

## [1.0.9] - 2026-03-02

Earlier releases are recorded in the
[GitHub releases](https://github.com/HiImSmiley/Socketley/releases).
