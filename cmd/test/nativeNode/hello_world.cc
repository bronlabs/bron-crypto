#include <napi.h>
#include "awesome.h"

Napi::String SayHi(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  return Napi::String::New(env, "Hi!");
}

Napi::Number Test(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::HandleScope scope(env);

  using namespace std;
  if (info.Length() != 2 || !info[0].IsNumber() || !info[1].IsNumber())
  {
    Napi::TypeError::New(env, "Number expected").ThrowAsJavaScriptException();
  }

  long num1 = (long)info[0].ToNumber().Int64Value();
  long num2 = (long)info[1].ToNumber().Int64Value();

  double sum = Add(num1, num2);

  return Napi::Number::New(env, sum);
}

Napi::Object init(Napi::Env env, Napi::Object exports) {
    exports.Set(Napi::String::New(env, "sayHi"), Napi::Function::New(env, SayHi));
    exports.Set(Napi::String::New(env, "test"), Napi::Function::New(env, Test));
    return exports;
};

NODE_API_MODULE(hello_world, init);
