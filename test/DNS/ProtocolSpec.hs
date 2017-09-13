{-# LANGUAGE OverloadedStrings #-}
module DNS.ProtocolSpec where

import Test.Hspec
import DNS.Protocol

spec :: Spec
spec = do
  describe "mkDNSNameFromStr" $ do
    it "Creates correct dns name from a string" $
      mkDNSNameFromStr "www.google.com" `shouldBe` DNSName [DNSLabel "www", DNSLabel "google", DNSLabel "com"]
  describe "mkLabelFromStr" $ do
    it "Creates correct label from a string" $ mkLabelFromStr "Hello" `shouldBe` DNSLabel "Hello"
  describe "nullLabel" $ do
    it "Detects a null label" $ nullLabel (DNSLabel "") `shouldBe` True
    it "Correctly checks a label" $ nullLabel (DNSLabel "Hello") `shouldBe` False
