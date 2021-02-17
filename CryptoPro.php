<?php

class CryptoPro {

    //private $sTsp = "http://tsp.cryptopro.ru/tsp2012/";
    private $sTsp = "http://tsp.cryptopro.ru/tsp2012/tsp.srf";
    private $oStore;
    public $sError;

    /**
     * Подписать контент
     *
     * @param string $sContent
     * @param string $sHash
     * @return bool|string
     */
    public function createSign(string $sContent, string$sHash)
    {
        try
        {
            $oStore = $this->getStore();
            $oCert = $this->getCertificate($sHash);
            if (!$oCert) {
                return $this->sError;
            }
            $oSigner = new CPSigner();
            $oSigner->set_TSAAddress($this->sTsp);
            $oSigner->set_Certificate($oCert);
            $oSigner->set_Options(CERTIFICATE_INCLUDE_WHOLE_CHAIN);

            $oSignedData = new CPSignedData();
            $oSignedData->set_ContentEncoding(BASE64_TO_BINARY);
            $oSignedData->set_Content($sContent);
            $sSignature = $oSignedData->SignCades($oSigner, 1, false, 0);
            //$sSignature = $oSignedData->Sign($oSigner, 0, ENCODE_BASE64);
            //$sSignature = $oSignedData->Sign($oSigner, 0, STRING_TO_UCS2LE);
            //$oSignedData->Verify($sSignature, 0, VERIFY_SIGNATURE_ONLY);
            return $sSignature;
        }
        catch (Exception $e)
        {
            $this->sError = $e->getMessage();
            return false;
        }
    }

    /**
     * Получить массив сертификатов
     *
     * @return array|bool
     */
    public function getCertificateList()
    {
        try
        {
            $oStore = $this->getStore();
            $oCertificates = $this->oStore->get_Certificates();
            $iCountSertififcates = $oCertificates->Count();
            $aCertificates = [];
            for ($i = 1; $i <= $iCountSertififcates; $i++) {
                if (!$oCertificates->Item($i)->isValid()->get_Result()) {
                    continue;
                }
                $aCertificates[] = [
                    'subjectName' => $oCertificates->Item($i)->get_SubjectName(),
                    'validToDate' => $oCertificates->Item($i)->get_ValidToDate(),
                ];
            }
            return $aCertificates;
        }
        catch (Exception $e)
        {
            $this->sError = $e->getMessage();
            return false;
        }
    }

    /**
     * Получить версию CSP
     *
     * @return bool
     */
    public function getVersion()
    {
        try
        {
            $oAbout = new About();
            $oCSPVersion = $oAbout->CSPVersion();
            return $oCSPVersion->toString();
        }
        catch (Exception $e)
        {
            $this->sError = $e->getMessage();
            return false;
        }
    }

    /**
     * Открытие Store
     */
    private function getStore()
    {
        $this->oStore = new CPStore();
        $this->oStore->Open(CURRENT_USER_STORE, "MY", STORE_OPEN_READ_ONLY);
    }

    /**
     * Сертификат по хешу
     *
     * @param string $sHash
     * @return bool
     */
    private function getCertificate(string $sHash)
    {
        $oCertificates = $this->oStore->get_Certificates();
        if (!$oCertificates->Count()) {
            $this->sError = 'В хранилище не найдены сертификаты';
            return false;
        }
        $oCertificates = $oCertificates->Find(CERTIFICATE_FIND_SHA1_HASH, $sHash, 0);
        if (!$oCertificates->count()) {
            $this->sError = 'Сертификат с данным хешем не найден';
            return false;
        }
        if (!$oCertificates->Item(1)->isValid()->get_Result()) {
            $this->sError = 'Данный сертификат не валиден';
            return false;
        }
        return $oCertificates->Item(1);
    }
}
