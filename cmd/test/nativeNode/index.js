const hello_world = require('bindings')('hello_world')

console.log(hello_world.sayHi());


const foo = hello_world.test(2, 4)

console.log(foo)
