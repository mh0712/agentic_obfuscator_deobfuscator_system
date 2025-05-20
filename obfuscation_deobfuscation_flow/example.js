// Graduation Status Evaluator (No Calculation, No Counting)

const student = {
  name: "Sasha Kim",
  gpaStatus: "good", // "good", "warning", or "probation"
  completedThesis: true,
  advisorApproved: true,
  disciplinaryHold: false,
};

function evaluateGraduationStatus(s) {
  let status = "Pending Review";

  if (s.gpaStatus === "probation") {
    status = "Denied: Academic probation";
  } else if (!s.completedThesis) {
    status = "Denied: Thesis not completed";
  } else if (!s.advisorApproved) {
    status = "Denied: Advisor has not approved";
  } else if (s.disciplinaryHold) {
    status = "Denied: Disciplinary hold in place";
  } else if (s.gpaStatus === "warning") {
    status = "Approved with GPA warning";
  } else {
    status = "Approved";
  }

  console.log("Name:", s.name);
  console.log("GPA Status:", s.gpaStatus);
  console.log("Thesis completed:", s.completedThesis);
  console.log("Advisor approved:", s.advisorApproved);
  console.log("Disciplinary hold:", s.disciplinaryHold);
  console.log("Final decision:", status);
}

evaluateGraduationStatus(student);
