(herald "TLS 1.3 Protocol Analyser"
	(algebra diffie-hellman))


;;using macros for handshake property(pg 62)
;;(defmacro (handshake n a b)

;;  (^ (send (enc "hello" a b n (pubk b))) (recv (enc "hello-received" a n (pubk a))))

;;working of the protocol using psk

(defprotocol tls diffie-hellman

 ;; client side
 (defrole init
 (vars (a b name)(m text)(psk skey)(alpha rndx)(v base))
  (trace
   ;;(send (enc m a psk))
   
   (send (exp (gen) alpha))
   (recv v)
   (send (enc m (hash (exp v alpha))))))
   ;;(recv (cat "Server finished"))))

 ;;server side
 (defrole resp
  (vars (a b name)(m text)(psk skey)(beta rndx)(u base))
   (trace 
   ;;(recv (enc m a psk))
    (recv u)
    (send (exp (gen) beta))
    (recv (enc m (hash (exp u beta))))))
    ;;(send (cat "server finished")))))
(defrole mal
  (vars (a b name)(m text)(psk skey)(beta rndx)(u base))
  (trace
   (recv u)
   (send (exp (gen) beta))
   (recv (enc m (hash (exp u beta)))))))
  
 ;;skeleton for client point of view
(defskeleton tls
  (vars (a b name)(m text)(psk skey)(alpha beta rndx)(v u base))
  (defstrand init 3 (m m)(v v)(alpha alpha))
  (defstrand resp 3 (m m)(u u)(beta beta))
  ;;(defstrand mal 3 (b b)(a a))
  (uniq-gen alpha beta)
  (uniq-orig m))
  ;;(pen-non-orig psk))
 


;; skeleton for receiver point of view
;;(defskeleton tls
;; (vars (a b e name)(m text)(psk skey))
;; (defstrand response 1  (b b)(a a)(a e)(m m))
;; (defstrand init 1  (b b)(a a)(m m)(psk psk))
;; (uniq-orig m k))

