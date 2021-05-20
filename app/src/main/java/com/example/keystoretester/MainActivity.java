package com.example.keystoretester;

import android.os.Bundle;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.util.Log;

import androidx.appcompat.app.AppCompatActivity;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class MainActivity extends AppCompatActivity {

    public static final String TAG = "******Message*******";
    public static final String KEY_ALIAS = "my-key";
    public static final byte[] MSG = "hello".getBytes(StandardCharsets.UTF_8);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        try {
            PublicKey pk = createKeyStoreEntry();
            byte[] sig = sign();
            verify(pk, sig);
        } catch (Exception e) {
            Log.e(TAG, "error", e);
        }
        setContentView(R.layout.activity_main);
    }

    private PublicKey createKeyStoreEntry() throws Exception {
        Log.d(TAG, "createKeyStoreEntry() - start");

        BigInteger n = new BigInteger("22757975781706710400496080708137281343518337388133427271870654636229814273986619980400800808258982975524322390311217972285290812863237749094806391413483200626532842400157572662713781507905677141075544373925307153592714934249256538730168445373552148520438266959346940608579758218874732261513729072260855090180650900089966437118273890368353818685907748125276082902079474389987565134663110400064773380142237409359499053632634872101531653965599392126599645656694697303495159410045184457718369212066133871168689972705320226122528915644230713659358190087524573394300807682168522084144065370041346443029331616632629688172161");
        BigInteger d = new BigInteger("504415159694688584299768556723099103176918050125061378529148141462229850580411031018567576189483716890667947858353348076792377027504942760668998948085846761016797096649153212541215808708953031933726767553560112346555653064806636870019437075375217435519578547701268649450124567691031348767929835383802235222003916985350503553003523961540181387795466631921253611349727792664448223629005641009861135015452704358055542180699481048251579269677889560679639930383628505732607616869538868112448955884157290838792910063637040568090320478159311846651895774335442023988160709857845420639290032902408418308017059956345974295549");
        BigInteger e = new BigInteger("65537");

        BigInteger primeP = new BigInteger("163924600867055255673218225813796539361986518546784847299307645964413417806430099910103230845062404747491313584397420368573167867581656553389081198048086862404113126975040744890347748732079075887012600453975037034822851972189639702697187431757529389611900300796267778518461622254701384125682501047181187081469");
        BigInteger primeQ = new BigInteger("138831973122592450730819672256824892032655079583501765162512898908165842053759507408457627577670293111426430039745530815560459182605069767511594496474483967430621485792441596264037373989771826064555499605658267365990499554920894625107820374115826798943679838291341908789747478157726114045054158307693156653269");
        BigInteger primeExponentP = new BigInteger("40237652839591648961885066430665806013645377784490102362084961176579926640707402188898342533294458171306174552271255954182165059215193081379528346323444365099027539766047888414956806595556038478941234775822763031252501940531527746117302504153125338216376095013649690297488321363678245364143222825976223455141");
        BigInteger primeExponentQ = new BigInteger("110274153422794339308231210751198202231592731171685733056132741284518380059363488070169068788366949634685967348963079666979191345494751236974282666409444091254839740366683548760558608731122300038398173359661668462151173304102447329060114094251697206857381290905810372826938900513886668488477337456173992748257");
        BigInteger crt = new BigInteger("105903252377241981206822879772792554393351525846862767321679381302352918742319720326527031348389828502456328306139850461884708737053159581139015143552570594866419053179836934993473977763749656393073146680010425618909062593626364047888163538846074697206232078242491303591584607288718182258956599754443461206843");

        boolean crtKey = true;
        KeySpec keySpec = crtKey ?
                new RSAPrivateCrtKeySpec(n, e, d, primeP, primeQ, primeExponentP, primeExponentQ, crt) :
                new RSAPrivateKeySpec(n, d);


        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pk = kf.generatePublic(new RSAPublicKeySpec(n, e));
        PrivateKey sk = kf.generatePrivate(keySpec);

        Certificate[] dummy = new Certificate[]{new DummyCert()};

        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        KeyStore.PrivateKeyEntry entry = new KeyStore.PrivateKeyEntry(sk, dummy);
        KeyProtection protection = new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                .build();

        keyStore.setEntry(KEY_ALIAS, entry, protection);


        Log.d(TAG, "createKeyStoreEntry() - end");

        return pk;
    }

    private byte[] sign() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        PrivateKey key = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);

        Signature rsa_pss = Signature.getInstance("SHA256withRSA/PSS");
        rsa_pss.initSign(key);
        rsa_pss.update(MSG);
        return rsa_pss.sign();
    }

    private void verify(PublicKey pk, byte[] sig) throws Exception {
        Signature rsa_pss = Signature.getInstance("SHA256withRSA/PSS");
        rsa_pss.initVerify(pk);
        rsa_pss.update(MSG);
        boolean result = rsa_pss.verify(sig);

        Log.d(TAG, String.valueOf(result));
    }

}