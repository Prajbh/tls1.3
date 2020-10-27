(herald "TLS 1.3 Protocol Analyser"
	(algebra diffie-hellman))
;;finished key              
(defmacro (finkey)
  (hash (psk x y) "finished"))
;;psk
(defmacro (psk x y)
  (exp (gen) (mul x y)))
;;encryptedextension
(defmacro (encryptedextension a)
  (hash (finkey) a (psk x y) (hash "Initial Client-Hello" (exp (gen) x) "Initial Server-Hello" (exp (gen) y) a (psk x y))))
;;initial server finished
(defmacro (initserverfin x y)
  (hash (finkey) (hash "Initial Client-Hello" (exp (gen) x) "Initial Server-Hello" (exp (gen) y) (encryptedextension a))))
;; initial client finished
(defmacro (initclientfin x y)
  (hash (finkey) (hash "Initial Client-Hello" (exp (gen) x) "Initial Server-Hello" (exp (gen) y) (initserverfin x y))))
;;server finished	 
(defmacro (serverfinished index n1 n2)
  (hash (finkey) (hash "Client-Hello" n1 index "Server-Hello" n2)))
;;client finished
(defmacro (clientfinished index n1 n2)
  (hash (finkey) (hash "Client-hello" n1 index "Server-Hello" n2 (serverfinished index n1 n2))))

;;protocol for tls
(defprotocol tls diffie-hellman
;; Initial client side
  (defrole client-init
    (vars (x rndx)(ca a b name)(y expt) (n index text))
    (trace
     (send (cat "Initial Client-Hello" (exp (gen) x)))
     (recv (cat "Initial Server-Hello" (exp (gen) y) (encryptedextension a)(initserverfin x y)))
     (send (initclientfin x y))
     (init (cat "Client state" (psk x y))))
    (uniq-gen x))
  ;;(non-orig ca))
  
;;Initial server side
  (defrole server-init
    (vars (y rndx)(ca a b name)(x expt) (n index text))
    (trace
     (recv (cat "Initial Client-Hello" (exp (gen) x)))
     (send (cat "Initial Server-Hello" (exp (gen) y) (encryptedextension a) (initserverfin x y)))
     (recv (initclientfin x y))
     (init (cat "server record" (psk x y))))
    (uniq-gen y))
    ;;(non-orig ca)
;;client-side  
 (defrole init
   (vars (a b name)(m d text)(n1 n2 data)(x y rndx)(index text))
   (trace
    ;;(send a)
    ;;(recv index)
    (obsv (cat "Client state" (psk x y)))
    (send (cat "Client-hello" n1 index))
    (recv (cat "Server-hello" n2 (serverfinished index n1 n2)))
    (send (clientfinished index n1 n2)))
    (uniq-gen index)
   )
 ;;(recv (cat "hello-received" index)
 
;;server side                                   
 (defrole resp
  (vars (a b name)(m d text)(n1 n2 data)(x y rndx)(index text))
   (trace
    ;;(recv a)
    (obsv (cat "server record" (psk x y)))
    (recv (cat "Client-hello" n1 index))
    (send (cat "Server-hello" n2 (serverfinished index n1 n2)))
    (recv (clientfinished index n1 n2)))
   ;;(uniq-gen n2)
   ))

;;skeleton for client point of view              
(defskeleton tls
  (vars (a b name)(m d text)(n1 n2 data)(x y rndx)(index text))
  (defstrand init 4 (n1 n1)(index index)) 
  (uniq-orig n1)
  ;;(uniq-orig index)
  ;;(non-orig fkey)
  )
;;(pen-non-orig psk))                           
(defskeleton tls
  (vars (a b name)(m d text)(n1 n2 data)(x y rndx)(index text))
  (defstrand resp 4 (n2 n2)(index index))
  (uniq-orig n2)
  ;;(uniq-orig index)
  ;;(non-orig fkey)
)

;(defskeleton tls
;  (vars (a name)(psk skey))
;  (defstrand init 3 (a a)(psk psk))
;  (defstrand resp 3 (a b)(b a)(psk psk))         
;  (non-orig psk))
;;(pen-non-orig psk))                             
;(defskeleton tls
;  (vars (a b name)(psk skey))
;  (defstrand resp 2 (b b)(a a)(psk psk))
;  (non-orig psk))
