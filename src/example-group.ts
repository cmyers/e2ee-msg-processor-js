import { init as olmInit, InboundGroupSession, OutboundGroupSession } from '@matrix-org/olm';
// import { EncryptedMessage, MessageManager } from './MessageManager';
// import chalk from 'chalk';
// import { SessionManager } from './SessionManager';

(async () => {
    await olmInit();
    // const aliceSessionManager = new SessionManager('alice', 'alice');
    // const aliceMsgManager = new MessageManager(aliceSessionManager);

    // const alice2SessionManager = new SessionManager('alice', 'alice2');
    // const alice2MsgManager = new MessageManager(alice2SessionManager);

    // const bobSessionManager = new SessionManager('bob', 'bob');
    // const bobMsgManager = new MessageManager(bobSessionManager);

    // const bob2SessionManager = new SessionManager('bob', 'bob2');
    // const bob2MsgManager = new MessageManager(bob2SessionManager);

    // const charlieSessionManager = new SessionManager('charlie', 'charlie');
    // const charlieMsgManager = new MessageManager(charlieSessionManager);

    const outbound_session = new OutboundGroupSession();
    outbound_session.create();

    // exchange these over a secure channel
    const session_key = outbound_session.session_key();

    const inbound_session = new InboundGroupSession();
    inbound_session.create(session_key);

    const ciphertext = outbound_session.encrypt("Hello");
    const plaintext = inbound_session.decrypt(ciphertext);
    console.log(plaintext);


})();