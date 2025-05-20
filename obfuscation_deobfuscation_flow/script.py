student_name = "Alex"
degree_program = "Computer Science"
credits_completed = 120
credits_required = 120
gpa = 3.6

print("Checking graduation eligibility for:", student_name)
print("Degree Program:", degree_program)
print("Credits Completed:", credits_completed)
print("GPA:", gpa)

if credits_completed >= credits_required and gpa >= 2.0:
    print("Congratulations,", student_name + "! You are eligible to graduate.")
else:
    print("Sorry,", student_name + ". You are not eligible to graduate yet.")