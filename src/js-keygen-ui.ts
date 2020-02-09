// import {generateKeyPair} from './js-keygen';

// // TODO: any
// function copy(id: any) {
//   return function() {
//     var ta = document.querySelector(id);
//     ta.focus();
//     ta.select();
//     try {
//       var successful = document.execCommand("copy");
//       var msg = successful ? "successful" : "unsuccessful";
//       console.log("Copy key command was " + msg);
//     } catch (err) {
//       console.log("Oops, unable to copy");
//     }
//     window.getSelection()!.removeAllRanges();
//     ta.blur();
//   };
// }

// function buildHref(data: string) {
//   return "data:application/octet-stream;charset=utf-8;base64," + window.btoa(data);
// }

// // TODO: may any
// document.addEventListener("DOMContentLoaded", function() {
//   document.querySelector("#savePrivate")!.addEventListener("click", function() {
//     (document.querySelector("a#private") as any).click();
//   });
//   document.querySelector("#copyPrivate")!.addEventListener("click", copy("#privateKey"));
//   document.querySelector("#savePublic")!.addEventListener("click", function() {
//     (document.querySelector("a#public") as any).click();
//   });
//   document.querySelector("#copyPublic")!.addEventListener("click", copy("#publicKey"));

//   document.querySelector("#generate")!.addEventListener("click", function() {
//     var name = (document.querySelector("#name") as any).value || "name";
//     document.querySelector("a#private")!.setAttribute("download", name + "_rsa");
//     document.querySelector("a#public")!.setAttribute("download", name + "_rsa.pub");

//     var alg = (document.querySelector("#alg") as any).value || "RSASSA-PKCS1-v1_5";
//     var size = parseInt((document.querySelector("#size") as any).value || "2048", 10);
//     generateKeyPair(alg, size, name)
//       .then(function(keys: any) {
//         document.querySelector("#private")!.setAttribute("href", buildHref(keys[0]));
//         document.querySelector("#public")!.setAttribute("href", buildHref(keys[1]));
//         document.querySelector("#privateKey")!.textContent = keys[0];
//         document.querySelector("#publicKey")!.textContent = keys[1];
//         (document.querySelector("#result") as any).style.display = "block";
//       })
//       .catch(function(err: any) {
//         console.error(err);
//       });
//   });
// });
