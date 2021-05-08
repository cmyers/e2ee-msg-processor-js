import {Account, init as olmInit, Session} from 'olm';

(async () => {
    await olmInit();

    var aliceAccount = new Account();
    var bobAccount = new Account();
    aliceAccount.create();
    bobAccount.create();

    const aliceSession = new Session();
    const bobSession = new Session();

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
    console.log((encrypted as any).body);

    bobSession.create_inbound(bobAccount, (encrypted as any).body);
    bobAccount.remove_one_time_keys(bobSession);

    var decrypted = bobSession.decrypt((encrypted as any).type, (encrypted as any).body);

    console.log(TEST_TEXT, "->", decrypted);

    TEST_TEXT='Hello Alice!';
    encrypted = bobSession.encrypt(TEST_TEXT);
    console.log((encrypted as any).body );
    decrypted = aliceSession.decrypt((encrypted as any).type, (encrypted as any).body);
    console.log(TEST_TEXT, "->", decrypted);

})();