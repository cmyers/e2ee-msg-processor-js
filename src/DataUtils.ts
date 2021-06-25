export class DataUtils {
  static appendBuffer(buffer1: Buffer, buffer2: Buffer): Buffer {
    const tmp = Buffer.alloc(buffer1.byteLength + buffer2.byteLength);
    tmp.set(Buffer.from(buffer1), 0);
    tmp.set(Buffer.from(buffer2), buffer1.byteLength);
    return tmp;
  }
}