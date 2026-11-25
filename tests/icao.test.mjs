// Tests against the worked examples in ICAO Doc 9303 Part 11 (Appendix D: BAC + SM, Appendix G: PACE ECDH-GM).
import test from 'node:test';
import assert from 'node:assert/strict';
import { hex, fromHex, bytesToBig } from '../js/util/bytes.js';
import { checkDigit, mrzKeyString, parseMRZ } from '../js/icao/mrz.js';
import { deriveBacKeys, performBAC } from '../js/icao/bac.js';
import { SecureMessaging } from '../js/icao/sm.js';
import { performPACE } from '../js/icao/pace.js';
import { CURVES } from '../js/crypto/curves.js';

test('check digits & MRZ key string (ICAO example)', () => {
  assert.equal(checkDigit('L898902C<'), '3');
  assert.equal(mrzKeyString({ documentNumber: 'L898902C', dateOfBirth: '690806', dateOfExpiry: '940623' }), 'L898902C<369080619406236');
});

test('TD3 / TD1 MRZ parsing', () => {
  const td3 = parseMRZ('P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\nL898902C36UTO7408122F1204159ZE184226B<<<<<10');
  assert.equal(td3.format, 'TD3'); assert.equal(td3.surname, 'ERIKSSON'); assert.equal(td3.givenNames, 'ANNA MARIA');
  assert.equal(td3.documentNumber, 'L898902C3'); assert.ok(td3.valid, JSON.stringify(td3.checks));
  const td1 = parseMRZ('I<UTOD231458907<<<<<<<<<<<<<<<\n7408122F1204159UTO<<<<<<<<<<<6\nERIKSSON<<ANNA<MARIA<<<<<<<<<<');
  assert.equal(td1.format, 'TD1'); assert.equal(td1.documentNumber, 'D23145890'); assert.ok(td1.valid, JSON.stringify(td1.checks));
});

test('BAC key derivation (9303-11 App. D.2)', async () => {
  const k = await deriveBacKeys('L898902C<369080619406236');
  assert.equal(hex(k.kseed), '239AB9CB282DAF66231DC5A4DF6BFBAE');
  assert.equal(hex(k.kenc), 'AB94FDECF2674FDFB9B391F85D7F76F2');
  assert.equal(hex(k.kmac), '7962D9ECE03D1ACD4C76089DCE131543');
});

test('BAC mutual authentication + session keys (App. D.3)', async () => {
  const card = {
    async transmit(c) {
      if (c.ins === 0x84) return { data: fromHex('4608F91988702212'), sw: 0x9000 };
      assert.equal(hex(c.data), '72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F25F1448EEA8AD90A7');
      return { data: fromHex('46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449'), sw: 0x9000 };
    },
  };
  const sm = await performBAC(card, 'L898902C<369080619406236', { rndIFD: fromHex('781723860C06C226'), kIFD: fromHex('0B795240CB7049B01C19B33E32804F0B') });
  assert.equal(hex(sm.ksEnc), '979EC13B1CBFE9DCD01AB0FED307EAE5');
  assert.equal(hex(sm.ksMac), 'F1CB1F1FB5ADF208806B89DC579DC1F8');
  assert.equal(hex(sm.ssc), '887022120C06C226');
});

test('3DES secure messaging wrap/unwrap (App. D.4)', () => {
  const sm = new SecureMessaging({ cipher: '3DES', ksEnc: fromHex('979EC13B1CBFE9DCD01AB0FED307EAE5'), ksMac: fromHex('F1CB1F1FB5ADF208806B89DC579DC1F8'), ssc: fromHex('887022120C06C226') });
  // SELECT EF.COM
  assert.equal(hex(sm.wrapCommand({ cla: 0, ins: 0xa4, p1: 2, p2: 0x0c, data: fromHex('011E') })), '0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800');
  assert.equal(sm.unwrapResponse(fromHex('990290008E08FA855A5D4C50A8ED9000')).sw, 0x9000);
  // READ BINARY first 4 bytes
  assert.equal(hex(sm.wrapCommand({ cla: 0, ins: 0xb0, p1: 0, p2: 0, le: 4 })), '0CB000000D9701048E08ED6705417E96BA5500');
  const r = sm.unwrapResponse(fromHex('8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000'));
  assert.equal(hex(r.data), '60145F01');
});

test('PACE ECDH-GM brainpoolP256r1 AES-128 (App. G.1)', async () => {
  const info = { oid: '0.4.0.127.0.7.2.2.4.2.2', parameterId: 13, cipher: 'AES', keyBits: 128 };
  const pt = (x, y) => '04' + x + y;
  const chipMap = pt('824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57', '30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54');
  const chipEph = pt('9E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB', '7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094');
  const steps = [
    '7C12801095A3A016522EE98D01E76CB6B98B42C3',
    '7C438241' + chipMap,
    '7C438441' + chipEph,
    '7C0A86083ABB9674BCE93C08',
  ];
  let i = 0;
  const card = { async transmit(c) { if (c.ins === 0x22) return { data: new Uint8Array(0), sw: 0x9000 }; return { data: fromHex(steps[i++]), sw: 0x9000 }; } };
  const { debug, sm } = await performPACE(card, { type: 'MRZ', value: mrzKeyString({ documentNumber: 'T22000129', dateOfBirth: '640812', dateOfExpiry: '101031' }) }, info, {
    mapKey: bytesToBig(fromHex('7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99')),
    ephKey: bytesToBig(fromHex('A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595')),
  });
  assert.equal(hex(debug.kpi), '89DED1B26624EC1E634C1989302849DD');
  assert.equal(debug.s.toString(16).toUpperCase(), '3F00C4D39D153F2B2A214A078D899B22');
  assert.equal(debug.Gm.x.toString(16).toUpperCase(), '8CED63C91426D4F0EB1435E7CB1D74A46723A0AF21C89634F65A9AE87A9265E2');
  assert.equal(hex(debug.Kx), '28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925');
  assert.equal(hex(sm.ksEnc), 'F5F0E35C0D7161EE6724EE513A0D9A7F');
  assert.equal(hex(sm.ksMac), 'FE251C7858B356B24514B3BD5F4297D1');
  assert.equal(hex(debug.tPCD), 'C2B0BD78D94BA866');
  assert.ok(CURVES[13]);
});
