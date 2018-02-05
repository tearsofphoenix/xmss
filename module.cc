#include <node.h>
#include <node_buffer.h>

#include "xmss-reference/params.h"
#include "xmss-reference/xmss.h"

#include <fcntl.h>
#ifdef __unix__
#include <unistd.h>
#endif
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#define WINDOWS 1
#include <Windows.h>
#endif

#define XMSS_MLEN 32

#ifndef XMSS_SIGNATURES
#define XMSS_SIGNATURES 16
#endif

#ifdef XMSSMT
#define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_KEYPAIR xmssmt_keypair
    #define XMSS_SIGN xmssmt_sign
    #define XMSS_SIGN_OPEN xmssmt_sign_open
    #define XMSS_VARIANT "XMSSMT-SHA2_20/2_256"
#else
#define XMSS_PARSE_OID xmss_parse_oid
#define XMSS_STR_TO_OID xmss_str_to_oid
#define XMSS_KEYPAIR xmss_keypair
#define XMSS_SIGN xmss_sign
#define XMSS_SIGN_OPEN xmss_sign_open
#define XMSS_VARIANT "XMSS-SHA2_10_256"
#endif

namespace xmss {

using namespace v8;

static xmss_params params;
static uint32_t oid;

void GenKey(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();

  size_t pkLen = XMSS_OID_LEN + params.pk_bytes;
  size_t skLen = XMSS_OID_LEN + params.sk_bytes;

  unsigned char pk[pkLen];
  unsigned char sk[skLen];

  XMSS_KEYPAIR(pk, sk, oid);

  v8::Local<Object> obj = v8::Object::New(isolate);
  obj->Set(v8::String::NewFromUtf8(isolate, "private"), node::Encode(isolate, (const char*)sk, skLen, node::encoding::BUFFER));
  obj->Set(v8::String::NewFromUtf8(isolate, "public"), node::Encode(isolate, (const char*)pk, pkLen, node::encoding::BUFFER));
  args.GetReturnValue().Set(obj);
}

void signData(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();
  size_t msgLen = node::Buffer::Length(args[0]);
  unsigned char* msg = (unsigned char*)node::Buffer::Data(args[0]);

  unsigned char* sk = (unsigned char*)node::Buffer::Data(args[1]);


    unsigned long long smLen = params.sig_bytes + msgLen;
    v8::Local<v8::Value> outbuffer = node::Buffer::New(isolate, smLen).ToLocalChecked();

    XMSS_SIGN(sk, (unsigned char*)node::Buffer::Data(outbuffer), &smLen, msg, msgLen);

  v8::Local<v8::Object> output = v8::Object::New(isolate);
  output->Set(String::NewFromUtf8(isolate,"buffer"), outbuffer);
  output->Set(String::NewFromUtf8(isolate,"length"), Int32::NewFromUnsigned(isolate, (uint32_t)smLen));

  args.GetReturnValue().Set(output);
}

void verifyData(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();
  size_t smlen = node::Buffer::Length(args[0]);
  unsigned char* sm = (unsigned char*)node::Buffer::Data(args[0]);

  size_t msgLen = node::Buffer::Length(args[1]);

  unsigned char* pk = (unsigned char*)node::Buffer::Data(args[2]);

  unsigned long long mlen = msgLen;
  unsigned char *mout = (unsigned char *)malloc(mlen);

  int ret = XMSS_SIGN_OPEN(mout, &mlen, sm, smlen, pk);

  bool ok = ret == 0;

  free(mout);

  v8::Local<v8::Object> output = v8::Object::New(isolate);
  output->Set(0, v8::Boolean::New(isolate, ok));
  args.GetReturnValue().Set(output);
}

void init(Local<Object> exports) {
    XMSS_STR_TO_OID(&oid, XMSS_VARIANT);
    XMSS_PARSE_OID(&params, oid);

    NODE_SET_METHOD(exports, "createKeypair", GenKey);
    NODE_SET_METHOD(exports, "sign", signData);
    NODE_SET_METHOD(exports, "verify", verifyData);
}

NODE_MODULE(addon, init)
}
