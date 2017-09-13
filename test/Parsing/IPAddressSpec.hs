module Parsing.IPAddressSpec where

import Test.Hspec
import Parsing.IPAddress

main = hspec spec

spec = do
  describe "ipAddress" $ do
    it "Convertes 4 octets to a Word32 ipaddress" $
      ipAddress 127 0 0 1 `shouldBe` 2130706433
    it "Doesn't change the octets" $
      addressToOctets (ipAddress 127 0 0 1) `shouldBe` (127, 0, 0, 1)
  describe "addressToOctets" $
    it "Splits a word32 ipaddress to its individual octets" $
      addressToOctets 2034706200 `shouldBe` (121,71,39,24)
