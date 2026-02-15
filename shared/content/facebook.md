# Facebook Tracking -- The Most Complete Surveillance Machine Ever Built

Facebook (now Meta) operates the largest behavioral surveillance system ever constructed
by a private entity. With over 3 billion monthly active users and tracking infrastructure
embedded across millions of third-party websites and apps, Meta collects data at a scale
that exceeds any government intelligence program in history. This document explains
exactly how that system works, what data it collects, and what you can do about it.


## Off-Facebook Activity: The Invisible Web of Surveillance

The Meta Pixel (formerly the Facebook Pixel) is a tiny piece of JavaScript code embedded
on over 8.4 million websites worldwide. When you visit any of these sites -- even if you
are not logged into Facebook, even if you have never created a Facebook account -- the
pixel fires and sends data back to Meta's servers.

### What data the pixel sends

- The URL of every page you visit on the site
- The content of your shopping cart and any purchases you make
- Search queries you enter on the site
- Form submissions (including partial form data before you hit submit)
- Button clicks and navigation patterns
- Time spent on each page
- Your IP address, browser fingerprint, and device identifiers

### How it links to your identity

Meta matches this data to your Facebook profile using a combination of:

- **Facebook cookies** stored in your browser from previous sessions
- **Device fingerprinting** using screen resolution, installed fonts, timezone, browser
  plugins, and WebGL renderer information
- **Hashed email matching** -- many sites send hashed versions of your email to Meta,
  which matches them against its database of user emails
- **IP address correlation** combined with login patterns

Even if you clear your cookies, Meta can often re-identify you through deterministic
matching (email hashes) or probabilistic matching (device fingerprints combined with
behavioral patterns).

### The scale of the problem

A 2022 study by The Markup found Meta Pixel on 30% of the most popular websites on the
internet, including hospitals, tax preparation services, government benefit applications,
and crisis hotlines. Specific findings included:

- 33 of the top 100 US hospitals sent patient data to Meta via the pixel
- Tax preparation services sent income data, filing status, and refund amounts
- Federal student aid applications sent financial information
- Mental health and addiction recovery sites sent session and page view data

Meta claims this data is "aggregated and anonymized," but researchers have repeatedly
demonstrated that it is linked to individual user profiles and used for ad targeting.


## Shadow Profiles: Tracking People Who Never Signed Up

Facebook does not limit its data collection to people who have accounts. Through a
combination of contact uploads, pixel tracking, and cross-platform correlation, Meta
builds "shadow profiles" for non-users.

### How shadow profiles are constructed

1. **Contact uploads**: When any Facebook user syncs their phone contacts, every name,
   phone number, and email address is uploaded to Meta's servers. If 50 of your friends
   have your phone number and sync their contacts, Facebook has 50 independent
   confirmations of your identity and social connections -- even if you have never
   touched the platform.

2. **Meta Pixel data**: When you browse sites with the Meta Pixel, your browsing data is
   collected and stored. Meta correlates this data using device fingerprints and hashed
   identifiers to build a profile even without a logged-in session.

3. **Instagram and WhatsApp cross-referencing**: If you use Instagram or WhatsApp (both
   owned by Meta), data from those platforms is combined. WhatsApp metadata (who you
   message, when, how often) is linked to your shadow profile.

4. **IP and WiFi correlation**: When you are on the same WiFi network as Facebook users,
   Meta can infer your physical proximity and potential relationships.

### What shadow profiles contain

According to data obtained through GDPR subject access requests and court proceedings,
shadow profiles can contain:

- Your name, phone number(s), and email address(es)
- Your inferred social connections and relationship types
- Your approximate location history (derived from friends' data)
- Your browsing interests (derived from pixel data)
- Your inferred demographics (age range, gender, income bracket)
- Your political and religious affiliations (inferred from social graph)

There is no way to view, correct, or delete a shadow profile. Meta has acknowledged
their existence in congressional testimony but has never provided a mechanism for
non-users to access or remove their data.


## Ad Targeting: 98+ Data Points About Every User

Facebook's advertising platform is the most granular behavioral targeting system ever
made available to the general public. Anyone with a credit card can target ads to users
based on an extraordinarily detailed set of attributes.

### Categories of data used for targeting

**Demographics and identity:**
- Age, gender, relationship status, education level
- Job title, employer, industry
- Household composition, number of children, children's ages
- Homeownership status, home value, home type
- Income bracket, net worth estimate

**Behaviors and purchases:**
- Online and offline purchase history (via data broker partnerships)
- Credit card usage patterns
- Vehicle ownership (make, model, year, purchase date)
- Travel patterns and frequency
- Device ownership and mobile carrier
- Operating system and browser preferences

**Interests and beliefs:**
- Political affiliation and engagement level
- Religious affiliation
- Health and wellness interests (which Meta says it restricts but researchers
  have shown still functions through proxy categories)
- Media consumption patterns
- Brand affinities and purchase intent signals

**Life events and predictions:**
- Recently moved, recently engaged, recently had a baby
- Upcoming anniversary, upcoming birthday
- Likely to move (predictive)
- Likely to change jobs (predictive)

### How predictions are made

Meta's machine learning models analyze your behavioral patterns -- what you like, share,
click, linger on, scroll past, search for, and message about -- to predict future
actions. Internal documents revealed during the 2021 Frances Haugen whistleblower
disclosures showed that Meta's models can predict:

- Whether a teenager is feeling "insecure" or "worthless" (used for ad targeting)
- When a user is most emotionally vulnerable (optimizing ad delivery timing)
- Purchase intent days before the user consciously decides to buy
- Political persuadability for election advertising


## Face Recognition: DeepFace and Biometric Surveillance

Facebook's DeepFace system, published in 2014, achieves 97.35% accuracy on the Labeled
Faces in the Wild benchmark -- approaching human-level performance at 97.53%. This system
was trained on the largest facial recognition dataset ever assembled: billions of tagged
photos uploaded by Facebook users.

### How DeepFace works

1. **Detection**: When any photo is uploaded, DeepFace detects all faces in the image
2. **Alignment**: Each face is normalized to a standard 3D model to account for pose,
   lighting, and expression variations
3. **Representation**: A 128-dimensional vector (called a "faceprint") is computed for
   each face using a deep neural network
4. **Classification**: The faceprint is compared against Facebook's database of stored
   faceprints to find matches

### Why this matters

- You can be identified in photos you did not upload and did not consent to
- Your faceprint persists as a mathematical object even if you delete your photos
- Group photos at public events can be used to place you at specific locations and times
- The system works on partial faces, sunglasses, and significant appearance changes
- Facebook's training data has been used to improve facial recognition systems sold to
  law enforcement and government agencies

### Legal consequences

In 2021, Facebook settled a class-action lawsuit in Illinois for $650 million over
violations of the Biometric Information Privacy Act (BIPA) related to face recognition.
Facebook subsequently announced it would "shut down" its face recognition system, but
Meta's terms of service still permit biometric data collection, and the underlying
DeepFace technology remains in Meta's portfolio.


## Cross-Platform Tracking: The Meta Ecosystem

Meta operates four of the ten most-used communication platforms globally:

- **Facebook** (3+ billion monthly active users)
- **Instagram** (2+ billion monthly active users)
- **WhatsApp** (2+ billion monthly active users)
- **Messenger** (1+ billion monthly active users)

Additionally, Meta collects data through:

- **Meta Quest** (VR headsets) -- eye tracking, hand tracking, room geometry, voice data
- **Threads** -- social media activity
- **Meta Audience Network** -- ad serving across third-party apps
- **Meta Business Suite** -- business communications data

### How cross-platform data is combined

Since Meta merged its data infrastructure across platforms, activity on any Meta property
is combined into a unified profile. This means:

- Your WhatsApp contacts are correlated with your Facebook social graph
- Your Instagram browsing interests refine your Facebook ad targeting profile
- Your Messenger conversations inform content ranking across all platforms
- Your Meta Quest VR usage data (including physical movement patterns, eye tracking data,
  and room layout) is linked to your advertising profile

Meta's internal documents, revealed during antitrust proceedings, show that cross-platform
data integration was a primary motivation for acquiring Instagram and WhatsApp.


## Data Broker Partnerships

Until 2018, Facebook maintained formal "Partner Categories" relationships with major data
brokers including:

- **Acxiom** (now LiveRamp) -- offline purchase data, household demographics
- **Experian** -- credit data, financial behavior, property records
- **Oracle Data Cloud** (formerly Datalogix and BlueKai) -- purchase receipts, loyalty
  card data, magazine subscriptions
- **Epsilon** -- direct mail response data, catalog purchases

Facebook officially ended these partnerships after the Cambridge Analytica scandal, but
advertisers can still upload their own customer data (including data purchased from
brokers) via Custom Audiences. The data broker information already collected remains in
Meta's systems, and Meta's own first-party data collection has expanded to fill the gap.

### What data brokers provided

- Grocery store loyalty card purchases linked to your real name
- Credit card transaction history categorized by merchant type
- Vehicle registration records
- Property ownership and mortgage information
- Magazine and newspaper subscriptions
- Charitable donation history
- Voter registration records and voting frequency


## Cambridge Analytica: The Political Manipulation Precedent

In 2018, it was revealed that Cambridge Analytica, a political consulting firm, had
harvested data from up to 87 million Facebook users through a personality quiz app called
"thisisyourdigitallife." The app was used by approximately 270,000 people, but Facebook's
API allowed it to also collect data from all of their friends.

### What Cambridge Analytica did with the data

- Built psychographic profiles categorizing users by personality traits (OCEAN model)
- Identified "persuadable" voters in swing states
- Targeted those voters with tailored political advertising designed to exploit their
  specific psychological vulnerabilities
- The data was used in the 2016 US presidential election and the Brexit referendum

### The systemic problem

Cambridge Analytica was not an isolated incident. It exposed a systemic design choice:
Facebook had built a platform where third-party apps could access vast amounts of user
data with minimal oversight. While Facebook tightened API access after the scandal, the
fundamental business model -- collecting maximum data and selling access to advertisers --
remains unchanged.

Facebook's own internal research, leaked by Frances Haugen in 2021, showed that the
company was aware that its algorithms amplified divisive political content because
engagement-driven ranking naturally promotes outrage and conflict.


## What a VPN Does Not Protect

A common misconception is that using a VPN protects you from Facebook tracking. It does
not, for the following reasons:

### Logged-in tracking

When you are logged into Facebook (or any Meta service), your activity is tied to your
account regardless of your IP address. A VPN changes your IP, but your session cookies,
account ID, and device fingerprint remain the same.

### Meta Pixel tracking

The Meta Pixel identifies you through cookies and browser fingerprinting, not IP address.
A VPN does not prevent cookies from being set or read, and it does not change your browser
fingerprint. The pixel fires normally through VPN connections.

### App-level tracking

Facebook's mobile app collects device-level identifiers (IDFA on iOS, GAID on Android),
WiFi network names, Bluetooth beacons, accelerometer data, and GPS coordinates. None of
this data passes through a VPN tunnel.

### Cross-device correlation

Meta correlates activity across your devices using account linkage, IP patterns, and
behavioral fingerprinting. Even if you use a VPN on one device, your other devices
continue to provide location and behavioral data.

### What actually helps

- **Browser compartmentalization**: Use Facebook only in a dedicated browser or container
  (e.g., Firefox Multi-Account Containers) to prevent pixel tracking on other sites
- **Ad blockers**: uBlock Origin blocks the Meta Pixel on third-party sites
- **Mobile app removal**: Delete the Facebook app and use the mobile website in a
  privacy-focused browser instead
- **DNS-level blocking**: Use Pi-hole or NextDNS to block Meta tracking domains at the
  network level


## Concrete Hardening Steps

The following steps are ordered by impact, from most critical to least:

### Critical priority

1. **Disconnect Off-Facebook Activity**: Settings > Your Facebook Information >
   Off-Facebook Activity > Clear history, then toggle "Disconnect future Off-Facebook
   Activity" ON. This is the single most impactful setting change you can make.

2. **Set all posts to Friends only**: Settings > Privacy > Who can see your future
   posts > Friends. Then use the "Limit Past Posts" tool to retroactively restrict
   all previous public posts.

3. **Disable face recognition**: Settings > Face Recognition > toggle OFF. If this
   option is not available, it may have been removed in your region.

### High priority

4. **Disable ad personalization**: Settings > Ads > Ad Settings > Data about your
   activity from partners > Not allowed. Also review "Categories used to reach you"
   and remove all categories.

5. **Disable contact/call log syncing**: Settings > Your Facebook Information > Upload
   contacts > disable on all devices. Delete previously uploaded contacts.

6. **Disable location history**: Settings > Location > Location History > toggle OFF.
   Clear your location history.

7. **Hide your friend list**: Settings > Privacy > Who can see your friends list >
   Only me.

8. **Restrict profile searchability**: Settings > Privacy > Who can look you up using
   your email address > Friends. Same for phone number. Disable search engine indexing.

9. **Enable two-factor authentication**: Settings > Security and Login > Two-Factor
   Authentication. Use an authenticator app, not SMS (which is vulnerable to SIM-swap
   attacks).

10. **Review and remove third-party apps**: Settings > Apps and Websites > remove all
    apps you do not actively use and trust.

### Medium priority

11. **Enable login alerts**: Settings > Security and Login > Get alerts about
    unrecognized logins > enable all notification methods.

12. **Disable search engine indexing**: Settings > Privacy > Do you want search engines
    outside of Facebook to link to your profile > No.

13. **Review ad preferences**: Settings > Ads > Ad Preferences > review your "Interest
    categories" and "Advertisers" lists. Remove everything.

14. **Download your data archive**: Settings > Your Facebook Information > Download Your
    Information. Review what Facebook has collected about you. This is your right under
    GDPR and CCPA.

### Beyond settings: structural defenses

- Use Firefox with Multi-Account Containers to isolate Facebook in its own container
- Install uBlock Origin to block Meta Pixel and tracking scripts across the web
- Delete the Facebook mobile app and access via mobile browser with tracking protection
- Use a DNS-level blocker (Pi-hole, NextDNS) to block Meta tracking domains network-wide
- Consider whether you need a Facebook account at all -- account deletion is the most
  effective privacy measure


## Further Reading

- The Markup, "Pixel Hunt" series -- investigative reporting on Meta Pixel tracking
  across hospitals, tax services, and government websites
- Frances Haugen's SEC disclosures and congressional testimony (2021) -- internal
  documents revealing Meta's awareness of platform harms
- Carissa Veliz, "Privacy Is Power" (2020) -- accessible overview of surveillance
  capitalism with extensive coverage of Facebook's practices
- Shoshana Zuboff, "The Age of Surveillance Capitalism" (2019) -- foundational analysis
  of behavioral data extraction as an economic system
- Electronic Frontier Foundation (EFF) -- ongoing coverage of Meta's privacy practices
  and advocacy for stronger protections
- GDPR enforcement actions against Meta -- multiple EU data protection authorities have
  fined Meta billions of euros for privacy violations, including a record 1.2 billion
  euro fine by Ireland's DPC in 2023
