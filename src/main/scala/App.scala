import java.util
import javax.naming.Context
import javax.naming.directory.{InitialDirContext, SearchControls}

import com.sun.jndi.ldap.LdapCtx
import org.xbill.DNS.{ARecord, Lookup, SRVRecord, Type}

import scala.util.Try
import scala.util.control.NonFatal

object Run extends App {
  val env = new util.Hashtable[String, String]()
  val domain = if (args.length > 0) args(0) else "alis.test"
  val user = if (args.length > 1) args(1) else "carsten.saager"
  val pass = if (args.length > 2) args(2) else "Fr4nce!!"
  val searchString = if (args.length > 3) args(3) else s"(&(objectClass=user)(sAMAccountName=$user))"
  val searchBase = domain.split('.').mkString("DC=", ",DC=", "")

  import Context._

  var queryRepeat = 1

  env.put(INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
  env.put(SECURITY_AUTHENTICATION, "simple")
  env.put(SECURITY_PRINCIPAL, s"$user@$domain")
  env.put(SECURITY_CREDENTIALS, pass)

  env.put(PROVIDER_URL, "ldap:///" + searchBase)



  queryRepeat = 1
  val lookup = new Lookup("_ldap._tcp." + domain, Type.SRV)
  Try(lookup.run()).map { records =>
    for (record <- records.collect { case s: SRVRecord => s }) {
      println(record)
      val addr = new Lookup(record.getAdditionalName()).run().collect { case a: ARecord => a }
      if (addr.isEmpty) println("No IP resolved ")
      else for (ip <- addr) {
        println(checkLdap(ip.getAddress.getHostAddress, record.getPort))
      }

    }
  } recover {
    case NonFatal(_) =>
      println(s"DNS search for SRV records failed with '${lookup.getErrorString}'")
  }

  for (_ <- 1 to 20) {
    println("Discovery of LDAP:")
    println(checkLdap(domain, 0))
    Thread.sleep(500)
    println(s"In domain '$domain' user '$user' pass '$pass' search '$searchString'")
    println(checkLdap(domain, 389)) //"alis-dc1-bng.alis.test ldap://alis-dc1-cdf.alis.test ldap://alis-dc1-hl.alis.test"
  }
  def checkLdap(ip: String, port: Int): Try[Int] = Try {
    if (port == 0)
      env.put(PROVIDER_URL, "ldap:///" + searchBase)
    else
      env.put(PROVIDER_URL, s"ldap://$ip:$port")
    val start = System.currentTimeMillis()
    val ctx = try {
      new InitialDirContext(env) {
        def ldap = defaultInitCtx match {
          case l: LdapCtx =>
            Try {
              val hf = l.getClass.getDeclaredField("hostname")
              hf.setAccessible(true)
              hf.get(l).toString
            }.getOrElse("<access failed>")
          case _ => "<can't read hostname>"
        }
      }
    } catch {
      case NonFatal(e) =>
        print(e)
        println(start - System.currentTimeMillis())
        throw e
    }
    ctx match {
      case c: {def ldap: String} => print(c.ldap)
      case _ =>
    }
    println(start - System.currentTimeMillis())
    withResource(ctx) { c =>

      val q = query(ip, if (port == 0) "" else searchBase) _
      (1 to queryRepeat).foldLeft(0)((_, _) => q(c))
    }

  }

  def query(ip: String, searchBase: String)(context: InitialDirContext): Int = {
    val searchControls = new SearchControls
    import SearchControls._
    searchControls.setReturningAttributes(Array("sAMAccountName"))
    searchControls.setSearchScope(SUBTREE_SCOPE)


    val values = timed {
      context.search(searchBase, searchString, searchControls)
    } { time =>
      println(s"Query via $ip took ${time}ms")
    }

    withResource(values)(identity(_))
  }

  def timed[T](call: => T)(out: Long => Unit): T = {
    val start = System.currentTimeMillis()
    try {
      call
    } finally {
      out(System.currentTimeMillis() - start)
    }
  }

  type UndeclaredClosable = {def close(): Unit}

  def withResource[T <: UndeclaredClosable, R](res: T)(body: T => R) = {
    try {
      body(res)
    } finally {
      res.close()
    }
  }

  implicit def enumCount(values: java.util.Enumeration[_]): Int = {

    var count = 0
    while (values.hasMoreElements) {
      count += 1
      values.nextElement()
    }
    count
  }
}
