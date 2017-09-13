module DNS.Protocol.ResourceRecordType where

import qualified Data.Binary.Bits.Get as Bits
import qualified Data.Binary.Bits.Put as Bits
import           Protolude

import           Parsing.BinaryBit

-- | There are three subcategories of 'ResourceRecordType' numbers: data TYPEs, QTYPEs, and Meta-TYPEs.
--
--   Data TYPEs are the means of storing data.  QTYPES can only be used in queries. Meta-TYPEs designate
--   transient data associated with a particular DNS message and, in some cases, can also be used in
--   queries. Thus far, data TYPEs have been assigned from 1 upward, plus the block from 100 through 103,
--   and from 32,768 upward, while Q and Meta-TYPEs have been assigned from 255 downward except for the OPT
--   Meta-RR, which is assigned TYPE 41.
data ResourceRecordType
  = RRA          -- ^ a host address                         (RFC1035)
  | RRNS         -- ^ an authoritative name server           (RFC1035)
  | RRMD         -- ^ a mail destination (OBSELETE)          (RFC1035)
  | RRMF         -- ^ a mail forwarder   (OBSELETE)          (RFC1035)
  | RRCNAME      -- ^ the canonical name for an alias        (RFC1035)
  | RRSOA        -- ^ marks the start of a zone of authority (RFC1035)
  | RRMB         -- ^ a mailbox domain name                  (RFC1035)
  | RRMG         -- ^ a mail group member                    (RFC1035)
  | RRMR         -- ^ a mail rename domain name              (RFC1035)
  | RRNULL       -- ^ a null RR                              (RFC1035)
  | RRWKS        -- ^ a well known service description       (RFC1035)
  | RRPTR        -- ^ a domain name pointer                  (RFC1035)
  | RRHINFO      -- ^ host information                       (RFC1035)
  | RRMINFO      -- ^ mailbox or mail list information       (RFC1035)
  | RRMX         -- ^ mail exchange                          (RFC1035)
  | RRTXT        -- ^ text strings	                         (RFC1035)
  | RRRP         -- ^ for Responsible Person	               (RFC1183)
  | RRAFSDB      -- ^ for AFS Data Base location	           (RFC1183, RFC5864)
  | RRX25        -- ^ for X.25 PSDN address	                 (RFC1183)
  | RRISDN       -- ^ for ISDN address	                     (RFC1183)
  | RRRT         -- ^ for Route Through	                     (RFC1183)
  | RRNSAP       -- ^ for NSAP address, NSAP style A record  (RFC1706)
  | RRNSAP_PTR   -- ^ for domain name pointer, NSAP style	   (RFC1348, RFC1637, RFC1706)
  | RRSIG        -- ^ for security signature	               (RFC4034, RFC3755, RFC2535, RFC2536, RFC2537, RFC2931, RFC3110, RFC3008)
  | RRKEY        -- ^ for security key	                     (RFC4034, RFC3755, RFC2535, RFC2536, RFC2537, RFC2539, RFC3008, RFC3110)
  | RRPX         -- ^ X.400 mail mapping information	       (RFC2163)
  | RRGPOS       -- ^ Geographical Position	                 (RFC1712)
  | RRAAAA       -- ^ IP6 Address	                           (RFC3596)
  | RRLOC        -- ^ Location Information	                 (RFC1876)
  | RRNXT        -- ^ Next Domain (OBSOLETE)	               (RFC3755, RFC2535)
  | RREID        -- ^ Endpoint Identifier	                   (http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt)
  | RRNIMLOC     -- ^ Nimrod Locator	                       (http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt)
  | RRSRV        -- ^ Server Selection	                     (RFC2782)
  | RRATMA       -- ^ ATM Address	                           (ATM Forum Technical Committee, "ATM Name System, V2.0")
  | RRNAPTR      -- ^ Naming Authority Pointer	             (RFC2915, RFC2168, RFC3403)
  | RRKX         -- ^ Key Exchanger	                         (RFC2230)
  | RRCERT       -- ^ CERT	                                 (RFC4398)
  | RRA6         -- ^ A6 (OBSOLETE - use AAAA)	             (RFC3226, RFC2874, RFC6563)
  | RRDNAME      -- ^ DNAME	                                 (RFC6672)
  | RRSINK       -- ^ SINK	                                 (http://tools.ietf.org/html/draft-eastlake-kitchen-sink)
  | RROPT        -- ^ OPT	                                   (RFC6891, RFC3225)
  | RRAPL        -- ^ APL	                                   (RFC3123)
  | RRDS         -- ^ Delegation Signer	                     (RFC4034, RFC3658)
  | RRSSHFP      -- ^ SSH Key Fingerprint	                   (RFC4255)
  | RRIPSECKEY   -- ^ IPSECKEY	                             (RFC4025)
  | RRRRSIG      -- ^ RRSIG	                                 (RFC4034, RFC3755)
  | RRNSEC       -- ^ NSEC	                                 (RFC4034, RFC3755)
  | RRDNSKEY     -- ^ DNSKEY	                               (RFC4034, RFC3755)
  | RRDHCID      -- ^ DHCID	                                 (RFC4701)
  | RRNSEC3      -- ^ NSEC3	                                 (RFC5155)
  | RRNSEC3PARAM -- ^ NSEC3PARAM	                           (RFC5155)
  | RRTLSA       -- ^ TLSA	                                 (RFC6698)
  | RRSMIMEA     -- ^ S/MIME cert association	               (RFC8162)
  | RRHIP        -- ^ Host Identity Protocol	               (RFC8005)
  | RRNINFO      -- ^ NINFO	                                 (Jim_Reid)
  | RRRKEY       -- ^ RKEY	                                 (Jim_Reid)
  | RRTALINK     -- ^ Trust Anchor LINK	                     (Wouter_Wijngaards)
  | RRCDS        -- ^ Child DS	                             (RFC7344)
  | RRCDNSKEY    -- ^ DNSKEY the Child wants reflected in DS (RFC7344)
  | RROPENPGPKEY -- ^ OpenPGP Key	                           (RFC7929)
  | RRCSYNC      -- ^ Child-To-Parent Synchronization	       (RFC7477)
  | RRSPF        -- ^                                        (RFC7208)
  | RRUINFO      -- ^                                        (IANA-Reserved)
  | RRUID        -- ^                                        (IANA-Reserved)
  | RRGID        -- ^                                        (IANA-Reserved)
  | RRUNSPEC     -- ^                                        (IANA-Reserved)
  | RRNID        -- ^                                        (RFC6742)
  | RRL32        -- ^                                        (RFC6742)
  | RRL64        -- ^                                        (RFC6742)
  | RRLP         -- ^                                        (RFC6742)
  | RREUI48      -- ^ an EUI-48 address	                     (RFC7043)
  | RREUI64      -- ^ an EUI-64 address	                     (RFC7043)
  | RRTKEY       -- ^ Transaction Key	                       (RFC2930)
  | RRTSIG       -- ^ Transaction Signature	                 (RFC2845)
  | RRIXFR       -- ^ incremental transfer	                 (RFC1995)
  | RRAXFR       -- ^ transfer of an entire zone	           (RFC1035, RFC5936)
  | RRMAILB      -- ^ mailbox-related RRs (MB, MG or MR)	   (RFC1035)
  | RRMAILA      -- ^ mail agent RRs (OBSOLETE - see MX)	   (RFC1035)
  | RRWILDCARD   -- ^ A request for all records the server/cache has available (RFC1035, RFC6895)
  | RRURI        -- ^ URI	[RFC7553]
  | RRCAA        -- ^ Certification Authority Restriction	   (RFC6844)
  | RRAVC        -- ^ Application Visibility and Control	   (Wolfgang_Riedel)
  | RRDOA        -- ^ Digital Object Architecture	           (draft-durand-doa-over-dns)
  | RRTA         -- ^ DNSSEC Trust Authorities	             (Sam_Weiler)
  | RRDLV        -- ^ DNSSEC Lookaside Validation	           (RFC4431)
  deriving (Eq, Ord, Show)

instance BinaryPut ResourceRecordType where
  bput x = Bits.putWord16be 16 $ case x of
    RRA          -> 1
    RRNS         -> 2
    RRMD         -> 3
    RRMF         -> 4
    RRCNAME      -> 5
    RRSOA        -> 6
    RRMB         -> 7
    RRMG         -> 8
    RRMR         -> 9
    RRNULL       -> 10
    RRWKS        -> 11
    RRPTR        -> 12
    RRHINFO      -> 13
    RRMINFO      -> 14
    RRMX         -> 15
    RRTXT        -> 16
    RRRP         -> 17
    RRAFSDB      -> 18
    RRX25        -> 19
    RRISDN       -> 20
    RRRT         -> 21
    RRNSAP       -> 22
    RRNSAP_PTR   -> 23
    RRSIG        -> 24
    RRKEY        -> 25
    RRPX         -> 26
    RRGPOS       -> 27
    RRAAAA       -> 28
    RRLOC        -> 29
    RRNXT        -> 30
    RREID        -> 31
    RRNIMLOC     -> 32
    RRSRV        -> 33
    RRATMA       -> 34
    RRNAPTR      -> 35
    RRKX         -> 36
    RRCERT       -> 37
    RRA6         -> 38
    RRDNAME      -> 39
    RRSINK       -> 40
    RROPT        -> 41
    RRAPL        -> 42
    RRDS         -> 43
    RRSSHFP      -> 44
    RRIPSECKEY   -> 45
    RRRRSIG      -> 46
    RRNSEC       -> 47
    RRDNSKEY     -> 48
    RRDHCID      -> 49
    RRNSEC3      -> 50
    RRNSEC3PARAM -> 51
    RRTLSA       -> 52
    RRSMIMEA     -> 53
    RRHIP        -> 55
    RRNINFO      -> 56
    RRRKEY       -> 57
    RRTALINK     -> 58
    RRCDS        -> 59
    RRCDNSKEY    -> 60
    RROPENPGPKEY -> 61
    RRCSYNC      -> 62
    RRSPF        -> 99
    RRUINFO      -> 100
    RRUID        -> 101
    RRGID        -> 102
    RRUNSPEC     -> 103
    RRNID        -> 104
    RRL32        -> 105
    RRL64        -> 106
    RRLP         -> 107
    RREUI48      -> 108
    RREUI64      -> 109
    RRTKEY       -> 249
    RRTSIG       -> 250
    RRIXFR       -> 251
    RRAXFR       -> 252
    RRMAILB      -> 253
    RRMAILA      -> 254
    RRWILDCARD   -> 255
    RRURI        -> 256
    RRCAA        -> 257
    RRAVC        -> 258
    RRDOA        -> 259
    RRTA         -> 32768
    RRDLV        -> 32769

instance BinaryGet ResourceRecordType where
  bget = do
    rrt <- Bits.getWord16be 16
    return $ case rrt of
      1     -> RRA
      2     -> RRNS
      3     -> RRMD
      4     -> RRMF
      5     -> RRCNAME
      6     -> RRSOA
      7     -> RRMB
      8     -> RRMG
      9     -> RRMR
      10    -> RRNULL
      11    -> RRWKS
      12    -> RRPTR
      13    -> RRHINFO
      14    -> RRMINFO
      15    -> RRMX
      16    -> RRTXT
      17    -> RRRP
      18    -> RRAFSDB
      19    -> RRX25
      20    -> RRISDN
      21    -> RRRT
      22    -> RRNSAP
      23    -> RRNSAP_PTR
      24    -> RRSIG
      25    -> RRKEY
      26    -> RRPX
      27    -> RRGPOS
      28    -> RRAAAA
      29    -> RRLOC
      30    -> RRNXT
      31    -> RREID
      32    -> RRNIMLOC
      33    -> RRSRV
      34    -> RRATMA
      35    -> RRNAPTR
      36    -> RRKX
      37    -> RRCERT
      38    -> RRA6
      39    -> RRDNAME
      40    -> RRSINK
      41    -> RROPT
      42    -> RRAPL
      43    -> RRDS
      44    -> RRSSHFP
      45    -> RRIPSECKEY
      46    -> RRRRSIG
      47    -> RRNSEC
      48    -> RRDNSKEY
      49    -> RRDHCID
      50    -> RRNSEC3
      51    -> RRNSEC3PARAM
      52    -> RRTLSA
      53    -> RRSMIMEA
      55    -> RRHIP
      56    -> RRNINFO
      57    -> RRRKEY
      58    -> RRTALINK
      59    -> RRCDS
      60    -> RRCDNSKEY
      61    -> RROPENPGPKEY
      62    -> RRCSYNC
      99    -> RRSPF
      100   -> RRUINFO
      101   -> RRUID
      102   -> RRGID
      103   -> RRUNSPEC
      104   -> RRNID
      105   -> RRL32
      106   -> RRL64
      107   -> RRLP
      108   -> RREUI48
      109   -> RREUI64
      249   -> RRTKEY
      250   -> RRTSIG
      251   -> RRIXFR
      252   -> RRAXFR
      253   -> RRMAILB
      254   -> RRMAILA
      255   -> RRWILDCARD
      256   -> RRURI
      257   -> RRCAA
      258   -> RRAVC
      259   -> RRDOA
      32768 -> RRTA
      32769 -> RRDLV
      _     -> panic $ "Unknown record resource type received " <> show rrt

instance BinaryBit ResourceRecordType

