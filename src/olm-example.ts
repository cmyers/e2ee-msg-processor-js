var Olm = require('olm');

(async () => {
    await Olm.init();

    var aliceAccount = new Olm.Account();
    var bobAccount = new Olm.Account();
    aliceAccount.create();
    bobAccount.create();

    const aliceSession = new Olm.Session();
    const bobSession = new Olm.Session();


    bobAccount.generate_one_time_keys(1);
    var bobOneTimeKeys = JSON.parse(bobAccount.one_time_keys()).curve25519;
    bobAccount.mark_keys_as_published();

    var bobIdKey = JSON.parse(bobAccount.identity_keys()).curve25519;

    var otk_id = Object.keys(bobOneTimeKeys)[0];

    aliceSession.create_outbound(
        aliceAccount, bobIdKey, bobOneTimeKeys[otk_id]
    );

    var TEST_TEXT='Hello Bob';
    var encrypted = aliceSession.encrypt(TEST_TEXT);
    console.log(encrypted.body);

    bobSession.create_inbound(bobAccount, encrypted.body);
    bobAccount.remove_one_time_keys(bobSession);

    var decrypted = bobSession.decrypt(encrypted.type, encrypted.body);

    console.log(TEST_TEXT, "->", decrypted);

    TEST_TEXT='Hello Alice!';
    encrypted = bobSession.encrypt(TEST_TEXT);
    console.log(encrypted.body);
    decrypted = aliceSession.decrypt(encrypted.type, encrypted.body);
    console.log(TEST_TEXT, "->", decrypted);

})();