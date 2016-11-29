require 'socket'
require 'openssl'
require 'thread'
require 'openssl'
require 'base64'
require 'rubygems'  
require 'active_record' 
require 'fileutils'
require 'bcrypt'
require './encrypto_signo.rb'
ActiveRecord::Base.establish_connection(  
:adapter=> "mysql2",  
:host => "localhost",  
:database=> "lpv",
:username=> "root",
:password => "codefellas"
)  
  

class Users < ActiveRecord::Base  
end  

class Userkey < ActiveRecord::Base  
end 

class Storedpasswords < ActiveRecord::Base  
end  

class Accesslist < ActiveRecord::Base
end

class Group < ActiveRecord::Base  
end

class Groupacclist < ActiveRecord::Base  
end

class Globalcap < ActiveRecord::Base  
end

class Domaincap < ActiveRecord::Base  
end

class Groupcap < ActiveRecord::Base  
end

if ARGV.length < 3
  puts "Usage: ruby #{__FILE__} port ssl_cert_path ssl_key_path"
  exit 1
end

#Adds the user-password pair to the database
def add_user(userName, password)
  usr=Globalcap.find_by(username: $logged_in_user)
  if(usr.adduser==false)
	return "You aren't authorized"
  end
  $userflag=0
  user = Users.find_by(username: userName)
  if (user!=nil)
    return "User exists"
  else
  
  	#$user_passwords[username] = password
  	Users.create(:username => userName, :password => password)	
	Globalcap.create(:username=>userName, :adduser=>0, :deluser=>0, :adddomain=>0, :deldomain=>0, :addgroup=>0, :delgroup=>0, :adjust=>0)
	return "User added"
  end
end

def changeuserpass(pass)
	password=BCrypt::Password.create(pass)
	Users.connection.execute("UPDATE users SET password=\"#{password}\" WHERE username=\"#{$logged_in_user}\";")
	return "User password is changed"
end

#Check if user credentials check out okay, and return true if so
def try_login(userName, pass)
  user = Users.find_by(username: userName)
  if(user!=nil && BCrypt::Password.new(user.password) == pass)
	return true
  else
	return false
  end
end

server  = TCPServer.new ARGV[0]
context = OpenSSL::SSL::SSLContext.new

context.cert = OpenSSL::X509::Certificate.new(File.open(ARGV[1]))
context.key  = OpenSSL::PKey::RSA.new(File.open(ARGV[2]), ARGV[3])

secure = OpenSSL::SSL::SSLServer.new(server, context)

puts "Listening securely on port #{ARGV[0]}..."

loop do
  Thread.new(secure.accept) do |conn|
    begin
      logged_in = false
	failed_logins = 0
	  conn.puts "Enter your username and password to login"
      while request = conn.gets

		if (failed_logins >= 3)
          conn.puts "Too many login attempts! Closing connection..."
          response = "quit"
          conn.puts response
          conn.sysclose
          break
        end

        request = request.chomp.strip
        req_array = request.split
        #puts req_array.join('.')

        $stdout.puts 'Got command: ' + request + " from " + conn.to_s
        response = "Server got command: #{request}"
			
        if (logged_in == false)
          if (req_array.length != 2)
            conn.puts "Please enter your username and password to login! (<username> <password>)"
          else
            logged_in = try_login(req_array[0], req_array[1])
            if (logged_in)
              conn.puts "logged in"
			  $logged_in_user = req_array[0]
			  conn.puts $logged_in_user
            else
              conn.puts "Wrong username or password"
			  failed_logins += 1
            end
          end
          next #Wait for the next command
        end

        #Take action
        if (request == "quit")
          $stdout.puts "Closing connection on client request..."
          response = "quit"
          conn.puts response
          conn.sysclose
          break

		elsif (req_array.length == 2 && req_array[0] == "getpass")
          conn.puts "getpass"	
		  conn.puts req_array[1]

		elsif (req_array.length == 2 && req_array[0] == "deluser")
          conn.puts "deluser"	
		  conn.puts req_array[1]

		elsif (req_array.length == 2 && req_array[0] == "delgroup")
          conn.puts "delgroup"	
		  conn.puts req_array[1]

		elsif (req_array.length == 2 && req_array[0] == "addgroup")
          conn.puts "addgroup"	
		  conn.puts req_array[1]

		elsif (req_array.length == 2 && req_array[0] == "removedom")
          conn.puts "removedom"	
		  conn.puts req_array[1]

        elsif (req_array.length == 3 && req_array[0] == "adduser")
          newUsersPass = BCrypt::Password.create(req_array[2]) # Hash the users password
          #conn.puts "User added"
          conn.puts add_user(req_array[1], newUsersPass.to_s)
		  #if($userflag==1)	
		  #	response = "User exists"
		  #end

		elsif (req_array.length == 2 && req_array[0] == "changeuserpass")
          conn.puts changeuserpass(req_array[1])	

		elsif (req_array.length == 3 && req_array[0] == "storepass")
			conn.puts "storepass"
			conn.puts req_array[1]
			conn.puts req_array[2]
			#storepass(req_array[1], req_array[2])
			#response = "password stored"
			#if($storeflag==1)	
			#  	response = "Domain exists"
		  #end

		elsif (req_array.length == 3 && req_array[0] == "changepass")
			conn.puts "changepass"
			conn.puts req_array[1]
			conn.puts req_array[2]

		elsif (req_array.length == 3 && req_array[0] == "allow")
			conn.puts "allow"
			conn.puts req_array[1]
			conn.puts req_array[2]

		elsif (req_array.length == 3 && req_array[0] == "revokepass")
			conn.puts "revokepass"
			conn.puts req_array[1]
			conn.puts req_array[2]

		elsif (req_array.length == 3 && req_array[0] == "addtogroup")
			conn.puts "addtogroup"
			conn.puts req_array[1]
			conn.puts req_array[2]

		elsif (req_array.length == 3 && req_array[0] == "removefromgroup")
			conn.puts "removefromgroup"
			conn.puts req_array[1]
			conn.puts req_array[2]

		elsif (req_array.length == 3 && req_array[0] == "allowgroup")
			conn.puts "allowgroup"
			conn.puts req_array[1]
			conn.puts req_array[2]

		elsif (req_array.length == 4 && req_array[0] == "adjustglcaps")
			conn.puts "adjustglcaps"
			conn.puts req_array[1]
			conn.puts req_array[2]
			conn.puts req_array[3]

		elsif (req_array.length == 5 && req_array[0] == "adjustdomcaps")
			conn.puts "adjustdomcaps"
			conn.puts req_array[1]
			conn.puts req_array[2]
			conn.puts req_array[3]
			conn.puts req_array[4]

		elsif (req_array.length == 5 && req_array[0] == "adjustgroupcaps")
			conn.puts "adjustgroupcaps"
			conn.puts req_array[1]
			conn.puts req_array[2]
			conn.puts req_array[3]
			conn.puts req_array[4]

		elsif (req_array.length == 1 && req_array[0] == "help")
			conn.puts "help"

        else
          response = "Unknown Command!"
        end

        conn.puts response

      end

    rescue
      $stderr.puts $!
    end

  end
end
